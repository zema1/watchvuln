package ctrl

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	entSql "entgo.io/ent/dialect/sql"
	_ "github.com/go-sql-driver/mysql"
	"github.com/google/go-github/v53/github"
	"github.com/hashicorp/go-multierror"
	"github.com/jackc/pgx/v5/stdlib"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/kataras/golog"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
	"modernc.org/sqlite"

	"github.com/zema1/watchvuln/ent"
	"github.com/zema1/watchvuln/ent/migrate"
	"github.com/zema1/watchvuln/ent/vulninformation"
	"github.com/zema1/watchvuln/grab"
	"github.com/zema1/watchvuln/push"
)

func init() {
	sql.Register("sqlite3", &sqlite.Driver{})
	sql.Register("postgres", &stdlib.Driver{})
}

const (
	// InitPageLimit must >= UpdatePageLimit !
	InitPageLimit   = 3
	UpdatePageLimit = 1
)

type WatchVulnApp struct {
	config     *WatchVulnAppConfig
	textPusher push.TextPusher
	rawPusher  push.RawPusher

	log          *golog.Logger
	db           *ent.Client
	githubClient *github.Client
	grabbers     []grab.Grabber
	prs          []*github.PullRequest
}

func NewApp(config *WatchVulnAppConfig) (*WatchVulnApp, error) {
	config.Init()
	drvName, connStr, err := config.DBConnForEnt()
	if err != nil {
		return nil, err
	}
	textPusher, rawPusher, err := config.GetPusher()
	if err != nil {
		return nil, err
	}
	drv, err := entSql.Open(drvName, connStr)
	if err != nil {
		return nil, errors.Wrap(err, "failed opening connection to db")
	}
	db := drv.DB()
	db.SetMaxOpenConns(1)
	db.SetConnMaxLifetime(time.Minute * 1)
	db.SetMaxIdleConns(1)
	dbClient := ent.NewClient(ent.Driver(drv))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	if err := dbClient.Schema.Create(ctx, migrate.WithDropIndex(true), migrate.WithDropColumn(true)); err != nil {
		return nil, errors.Wrap(err, "failed creating schema resources")
	}

	var grabs []grab.Grabber
	for _, part := range config.Sources {
		part = strings.ToLower(strings.TrimSpace(part))
		switch part {
		case "chaitin":
			grabs = append(grabs, grab.NewChaitinCrawler())
		case "avd":
			grabs = append(grabs, grab.NewAVDCrawler())
		case "nox", "ti":
			grabs = append(grabs, grab.NewTiCrawler())
		case "oscs":
			grabs = append(grabs, grab.NewOSCSCrawler())
		case "seebug":
			grabs = append(grabs, grab.NewSeebugCrawler())
		case "threatbook":
			grabs = append(grabs, grab.NewThreatBookCrawler())
		case "struts2", "structs2":
			grabs = append(grabs, grab.NewStruts2Crawler())
		case "kev":
			grabs = append(grabs, grab.NewKEVCrawler())
		case "venustech":
			grabs = append(grabs, grab.NewVenustechCrawler())
		default:
			return nil, fmt.Errorf("invalid grab source %s", part)
		}
	}

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = http.ProxyFromEnvironment
	githubClient := github.NewClient(&http.Client{
		Timeout:   time.Second * 10,
		Transport: tr,
	})

	return &WatchVulnApp{
		config:       config,
		textPusher:   textPusher,
		rawPusher:    rawPusher,
		log:          golog.Child("[ctrl]"),
		db:           dbClient,
		githubClient: githubClient,
		grabbers:     grabs,
	}, nil
}

func (w *WatchVulnApp) Run(ctx context.Context) error {
	if *w.config.DiffMode {
		w.log.Info("running in diff mode, skip init vuln database")
		w.collectAndPush(ctx)
		w.log.Info("diff finished")
		return nil
	}

	w.log.Infof("initialize local database..")
	success, fail := w.initData(ctx)
	w.grabbers = success
	localCount, err := w.db.VulnInformation.Query().Count(ctx)
	if err != nil {
		return err
	}
	w.log.Infof("system init finished, local database has %d vulns", localCount)
	if !*w.config.NoStartMessage {
		providers := make([]*grab.Provider, 0, 10)
		failed := make([]*grab.Provider, 0, 10)
		for _, p := range w.grabbers {
			providers = append(providers, p.ProviderInfo())
		}
		for _, p := range fail {
			failed = append(failed, p.ProviderInfo())
		}
		msg := &push.InitialMessage{
			Version:        w.config.Version,
			VulnCount:      localCount,
			Interval:       w.config.IntervalParsed.String(),
			Provider:       providers,
			FailedProvider: failed,
		}
		if err := w.textPusher.PushMarkdown("WatchVuln 初始化完成", push.RenderInitialMsg(msg)); err != nil {
			return err
		}
		if err := w.rawPusher.PushRaw(push.NewRawInitialMessage(msg)); err != nil {
			return err
		}
	}

	w.log.Infof("ticking every %s", w.config.Interval)

	defer func() {
		msg := "注意: WatchVuln 进程退出"
		if err = w.textPusher.PushText(msg); err != nil {
			w.log.Error(err)
		}
		if err = w.rawPusher.PushRaw(push.NewRawTextMessage(msg)); err != nil {
			w.log.Error(err)
		}
		time.Sleep(time.Second)
	}()

	ticker := time.NewTicker(w.config.IntervalParsed)
	defer ticker.Stop()
	for {
		w.prs = nil
		w.log.Infof("next checking at %s\n", time.Now().Add(w.config.IntervalParsed).Format("2006-01-02 15:04:05"))

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			hour := time.Now().Hour()
			if hour >= 0 && hour < 7 {
				// we must sleep in this time
				w.log.Infof("sleeping..")
				continue
			}
			w.collectAndPush(ctx)
		}
	}
}

func (w *WatchVulnApp) collectAndPush(ctx context.Context) {
	vulns, err := w.collectUpdate(ctx)
	if err != nil {
		w.log.Errorf("failed to get updates, %s", err)
	}
	w.log.Infof("found %d new vulns in this ticking", len(vulns))
	for _, v := range vulns {
		if w.config.NoFilter || v.Creator.IsValuable(v) {
			dbVuln, err := w.db.VulnInformation.Query().Where(vulninformation.Key(v.UniqueKey)).First(ctx)
			if err != nil {
				w.log.Errorf("failed to query %s from db %s", v.UniqueKey, err)
				continue
			}
			if dbVuln.Pushed {
				w.log.Infof("%s has been pushed, skipped", v)
				continue
			}
			if v.CVE != "" && *w.config.EnableCVEFilter {
				// 同一个 cve 已经有其它源推送过了
				others, err := w.db.VulnInformation.Query().
					Where(vulninformation.And(vulninformation.Cve(v.CVE), vulninformation.Pushed(true))).All(ctx)
				if err != nil {
					w.log.Errorf("failed to query %s from db %s", v.UniqueKey, err)
					continue
				}
				if len(others) != 0 {
					ids := make([]string, 0, len(others))
					for _, o := range others {
						ids = append(ids, o.Key)
					}
					w.log.Infof("found new cve but other source has already pushed, others: %v", ids)
					continue
				}
			}

			// 如果配置了软件列表黑名单，不推送在黑名单内的漏洞
			if len(w.config.BlackKeywords) != 0 {
				shouldContinue := false
				for _, p := range w.config.BlackKeywords {
					if strings.Contains(strings.ToLower(v.Title), strings.ToLower(p)) {
						w.log.Infof("skipped %s as in product filter list", v)
						shouldContinue = true
					}
					// 黑名单就不检查 description 里的内容了, 容易漏推送
					// if strings.Contains(strings.ToLower(v.Description), strings.ToLower(p)) {
					// 	w.log.Infof("skipped %s as in product filter list", v)
					// 	continue
					// }
				}
				if shouldContinue {
					continue
				}
			}

			// 如果配置了软件列表白名单，仅推送在白名单内的漏洞
			if len(w.config.WhiteKeywords) != 0 {
				found := false
				for _, p := range w.config.WhiteKeywords {
					if strings.Contains(strings.ToLower(v.Title), strings.ToLower(p)) {
						found = true
						break
					}
					if strings.Contains(strings.ToLower(v.Description), strings.ToLower(p)) {
						found = true
						break
					}
				}
				if !found {
					w.log.Infof("skipped %s as not in product filter list", v)
					continue
				}
			}

			// find cve pr in nuclei repo
			if v.CVE != "" && !*w.config.NoGithubSearch {
				links, err := w.FindGithubPoc(ctx, v.CVE)
				if err != nil {
					w.log.Warn(err)
				}
				w.log.Infof("%s found %d links from github, %v", v.CVE, len(links), links)
				if len(links) != 0 {
					v.GithubSearch = grab.MergeUniqueString(v.GithubSearch, links)
					_, err = dbVuln.Update().SetGithubSearch(v.GithubSearch).Save(ctx)
					if err != nil {
						w.log.Warnf("failed to save %s references,  %s", v.UniqueKey, err)
					}
				}
			}
			w.log.Infof("Pushing %s", v)

			// 默认重试3次，如果有多种推送方式，禁用重置机制，避免出现一个成功一个失败，重试的话，成功那个会被重复推送
			i := 0
			for {
				if err := w.pushVuln(v); err == nil {
					// 如果两种推送都成功，才标记为已推送
					_, err = dbVuln.Update().SetPushed(true).Save(ctx)
					if err != nil {
						w.log.Errorf("failed to save pushed %s status, %s", v.UniqueKey, err)
					}
					w.log.Infof("pushed %s successfully", v)
					break
				} else {
					w.log.Errorf("failed to push %s, %s", v.UniqueKey, err)
				}
				i++
				if i > w.config.PushRetryCount {
					break
				}
				w.log.Infof("retry to push %s after 30s", v.UniqueKey)
				time.Sleep(time.Second * 30)
			}
		} else {
			w.log.Infof("skipped %s as not valuable", v)
		}
	}
}

func (w *WatchVulnApp) pushVuln(vul *grab.VulnInfo) error {
	var pushErr *multierror.Error

	if err := w.textPusher.PushMarkdown(vul.Title, push.RenderVulnInfo(vul)); err != nil {
		pushErr = multierror.Append(pushErr, err)
	}

	if err := w.rawPusher.PushRaw(push.NewRawVulnInfoMessage(vul)); err != nil {
		pushErr = multierror.Append(pushErr, err)
	}

	return pushErr.ErrorOrNil()
}

func (w *WatchVulnApp) Close() {
	_ = w.db.Close()
}

func (w *WatchVulnApp) initData(ctx context.Context) ([]grab.Grabber, []grab.Grabber) {
	var eg errgroup.Group
	eg.SetLimit(len(w.grabbers))
	var success []grab.Grabber
	var fail []grab.Grabber
	for _, grabber := range w.grabbers {
		gb := grabber
		eg.Go(func() error {
			source := gb.ProviderInfo()
			w.log.Infof("start to init data from %s", source.Name)
			initVulns, err := gb.GetUpdate(ctx, InitPageLimit)
			if err != nil {
				fail = append(fail, gb)
				return errors.Wrap(err, source.Name)
			}

			for _, data := range initVulns {
				if _, err = w.createOrUpdate(ctx, source, data); err != nil {
					fail = append(fail, gb)
					return errors.Wrap(errors.Wrap(err, data.String()), source.Name)
				}
			}
			success = append(success, gb)
			return nil
		})
	}
	err := eg.Wait()
	if err != nil {
		w.log.Error(errors.Wrap(err, "init data"))
	}
	return success, fail
}

func (w *WatchVulnApp) collectUpdate(ctx context.Context) ([]*grab.VulnInfo, error) {
	var eg errgroup.Group
	eg.SetLimit(len(w.grabbers))

	var mu sync.Mutex
	var newVulns []*grab.VulnInfo

	for _, grabber := range w.grabbers {
		gb := grabber
		eg.Go(func() error {
			source := gb.ProviderInfo()
			dataChan, err := gb.GetUpdate(ctx, UpdatePageLimit)
			if err != nil {
				return errors.Wrap(err, gb.ProviderInfo().Name)
			}
			hasNewVuln := false
			w.log.Infof("collected %d vulns from %s", len(dataChan), source.Name)

			for _, data := range dataChan {
				isNewVuln, err := w.createOrUpdate(ctx, source, data)
				if err != nil {
					return errors.Wrap(err, gb.ProviderInfo().Name)
				}
				if isNewVuln {
					w.log.Infof("found new vuln: %s", data)
					mu.Lock()
					newVulns = append(newVulns, data)
					mu.Unlock()
					hasNewVuln = true
				}
			}

			// 如果一整页漏洞都是旧的，说明没有更新，不必再继续下一页了
			if !hasNewVuln {
				return nil
			}
			return nil
		})
	}
	err := eg.Wait()
	return newVulns, err
}

func (w *WatchVulnApp) createOrUpdate(ctx context.Context, source *grab.Provider, data *grab.VulnInfo) (bool, error) {
	vuln, err := w.db.VulnInformation.Query().
		Where(vulninformation.Key(data.UniqueKey)).
		First(ctx)
	// not exist
	if err != nil {
		data.Reason = append(data.Reason, grab.ReasonNewCreated)
		newVuln, err := w.db.VulnInformation.
			Create().
			SetKey(data.UniqueKey).
			SetTitle(data.Title).
			SetDescription(data.Description).
			SetSeverity(string(data.Severity)).
			SetCve(data.CVE).
			SetDisclosure(data.Disclosure).
			SetSolutions(data.Solutions).
			SetReferences(data.References).
			SetPushed(false).
			SetTags(data.Tags).
			SetFrom(data.From).
			Save(ctx)
		if err != nil {
			return false, err
		}
		w.log.Infof("vuln %s(%s) created from %s", newVuln.Title, newVuln.Key, source.Name)
		return true, nil
	}

	// 如果一个漏洞之前是低危，后来改成了严重，这种可能也需要推送, 走一下高价值的判断逻辑
	asNewVuln := false
	if string(data.Severity) != vuln.Severity {
		w.log.Infof("%s from %s change severity from %s to %s", data.Title, data.From, vuln.Severity, data.Severity)
		data.Reason = append(data.Reason, fmt.Sprintf("%s: %s => %s", grab.ReasonSeverityUpdated, vuln.Severity, data.Severity))
		asNewVuln = true
	}
	for _, newTag := range data.Tags {
		found := false
		for _, dbTag := range vuln.Tags {
			if newTag == dbTag {
				found = true
				break
			}
		}
		// tag 有更新
		if !found {
			w.log.Infof("%s from %s add new tag %s", data.Title, data.From, newTag)
			data.Reason = append(data.Reason, fmt.Sprintf("%s: %v => %v", grab.ReasonTagUpdated, vuln.Tags, data.Tags))
			asNewVuln = true
			break
		}
	}

	// update
	newVuln, err := vuln.Update().SetKey(data.UniqueKey).
		SetTitle(data.Title).
		SetDescription(data.Description).
		SetSeverity(string(data.Severity)).
		SetCve(data.CVE).
		SetDisclosure(data.Disclosure).
		SetSolutions(data.Solutions).
		SetReferences(data.References).
		SetTags(data.Tags).
		SetFrom(data.From).
		Save(ctx)
	if err != nil {
		return false, err
	}
	w.log.Debugf("vuln %d updated from %s %s", newVuln.ID, newVuln.Key, source.Name)
	return asNewVuln, nil
}

func (w *WatchVulnApp) FindGithubPoc(ctx context.Context, cveId string) ([]string, error) {
	var eg errgroup.Group
	var results []string
	var mu sync.Mutex

	eg.Go(func() error {
		links, err := w.findGithubRepo(ctx, cveId)
		if err != nil {
			return errors.Wrap(err, "find github repo")
		}
		mu.Lock()
		defer mu.Unlock()
		results = append(results, links...)
		return nil
	})
	eg.Go(func() error {
		links, err := w.findNucleiPR(ctx, cveId)
		if err != nil {
			return errors.Wrap(err, "find nuclei PR")
		}
		mu.Lock()
		defer mu.Unlock()
		results = append(results, links...)
		return nil
	})
	err := eg.Wait()
	return results, err
}

func (w *WatchVulnApp) findGithubRepo(ctx context.Context, cveId string) ([]string, error) {
	w.log.Infof("finding github repo of %s", cveId)
	re, err := regexp.Compile(fmt.Sprintf("(?i)[\b/_]%s[\b/_]", cveId))
	if err != nil {
		return nil, err
	}
	lastYear := time.Now().AddDate(-1, 0, 0).Format("2006-01-02")
	query := fmt.Sprintf(`language:Python language:JavaScript language:C language:C++ language:Java language:PHP language:Ruby language:Rust language:C# created:>%s %s`, lastYear, cveId)
	result, _, err := w.githubClient.Search.Repositories(ctx, query, &github.SearchOptions{
		ListOptions: github.ListOptions{Page: 1, PerPage: 100},
	})
	if err != nil {
		return nil, err
	}
	var links []string
	for _, repo := range result.Repositories {
		if re.MatchString(repo.GetHTMLURL()) {
			links = append(links, repo.GetHTMLURL())
		}
	}
	return links, nil
}

func (w *WatchVulnApp) findNucleiPR(ctx context.Context, cveId string) ([]string, error) {
	w.log.Infof("finding nuclei PR of %s", cveId)
	if w.prs == nil {
		// 检查200个pr
		for page := 1; page < 2; page++ {
			prs, _, err := w.githubClient.PullRequests.List(ctx, "projectdiscovery", "nuclei-templates", &github.PullRequestListOptions{
				State:       "all",
				ListOptions: github.ListOptions{Page: page, PerPage: 100},
			})
			if err != nil {
				if len(w.prs) == 0 {
					return nil, err
				} else {
					w.log.Warnf("list nuclei pr failed: %v", err)
					continue
				}
			}
			w.prs = append(w.prs, prs...)
		}
	}

	var links []string
	re, err := regexp.Compile(fmt.Sprintf("(?i)[\b/_]%s[\b/_]", cveId))
	if err != nil {
		return nil, err
	}
	for _, pr := range w.prs {
		if re.MatchString(pr.GetTitle()) || re.MatchString(pr.GetBody()) {
			links = append(links, pr.GetHTMLURL())
		}
	}
	return links, nil
}
