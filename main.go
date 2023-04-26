package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	entSql "entgo.io/ent/dialect/sql"
	"github.com/kataras/golog"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
	"github.com/zema1/watchvuln/ent"
	"github.com/zema1/watchvuln/ent/migrate"
	"github.com/zema1/watchvuln/ent/vulninformation"
	"github.com/zema1/watchvuln/grab"
	"github.com/zema1/watchvuln/push"
	"golang.org/x/sync/errgroup"
	"modernc.org/sqlite"
)

func init() {
	sql.Register("sqlite3", &sqlite.Driver{})
}

var log = golog.Child("[main]")
var Version = "v0.9.0"

const MaxPageBase = 3

func main() {
	golog.Default.SetLevel("info")
	cli.VersionFlag = &cli.BoolFlag{
		Name:     "version",
		Aliases:  []string{"v"},
		Usage:    "print the version",
		Category: "[Other Options]",
	}
	cli.HelpFlag = &cli.BoolFlag{
		Name:     "help",
		Aliases:  []string{"h"},
		Usage:    "show help",
		Category: "[Other Options]",
	}

	app := cli.NewApp()
	app.Name = "watchvuln"
	app.Usage = "A high valuable vulnerability watcher and pusher"
	app.Version = Version

	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:     "dingding-access-token",
			Aliases:  []string{"dt"},
			Usage:    "webhook access token of dingding bot",
			Category: "[\x00Push Options]",
		},
		&cli.StringFlag{
			Name:     "dingding-sign-secret",
			Aliases:  []string{"ds"},
			Usage:    "sign secret of dingding bot",
			Category: "[\x00Push Options]",
		},
		&cli.StringFlag{
			Name:     "wechatwork-key",
			Aliases:  []string{"wk"},
			Usage:    "webhook key of wechat work",
			Category: "[\x00Push Options]",
		},
		&cli.StringFlag{
			Name:     "lark-access-token",
			Aliases:  []string{"lt"},
			Usage:    "webhook access token of lark",
			Category: "[\x00Push Options]",
		},
		&cli.StringFlag{
			Name:     "lark-sign-secret",
			Aliases:  []string{"ls"},
			Usage:    "sign secret of lark",
			Category: "[\x00Push Options]",
		},
		&cli.StringFlag{
			Name:     "serverchan-key",
			Aliases:  []string{"sk"},
			Usage:    "send key for server chan",
			Category: "[\x00Push Options]",
		},
		&cli.StringFlag{
			Name:     "webhook-url",
			Aliases:  []string{"webhook"},
			Usage:    "your webhook server url, ex: http://127.0.0.1:1111/webhook",
			Category: "[\x00Push Options]",
		},
		&cli.StringFlag{
			Name:     "sources",
			Aliases:  []string{"s"},
			Usage:    "set vuln sources",
			Value:    "avd,ti,oscs,seebug",
			Category: "[Launch Options]",
		},
		&cli.StringFlag{
			Name:     "interval",
			Aliases:  []string{"i"},
			Usage:    "checking every [interval], supported format like 30s, 30m, 1h",
			Value:    "30m",
			Category: "[Launch Options]",
		},
		&cli.BoolFlag{
			Name:     "enable-cve-filter",
			Usage:    "enable a filter that vulns from multiple sources with same cve id will be sent only once",
			Value:    true,
			Category: "[Launch Options]",
		},
		&cli.BoolFlag{
			Name:     "no-start-message",
			Aliases:  []string{"nm"},
			Usage:    "disable the hello message when server starts",
			Category: "[Launch Options]",
		},
		&cli.BoolFlag{
			Name:     "no-filter",
			Aliases:  []string{"nf"},
			Usage:    "ignore the valuable filter and push all discovered vulns",
			Category: "[Launch Options]",
		},
		&cli.BoolFlag{
			Name:     "debug",
			Aliases:  []string{"d"},
			Usage:    "set log level to debug, print more details",
			Value:    false,
			Category: "[Other Options]",
		},
	}
	app.Before = func(c *cli.Context) error {
		if c.Bool("debug") {
			golog.Default.SetLevel("debug")
		}
		return nil
	}
	app.Action = Action

	err := app.Run(os.Args)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			log.Fatal("user canceled")
		} else {
			log.Fatal(err)
		}
	}
}

func Action(c *cli.Context) error {
	ctx, cancel := signalCtx()
	defer cancel()

	pusher, err := initPusher(c)
	if err != nil {
		return err
	}
	grabbers, err := initSources(c)
	if err != nil {
		return err
	}

	noStartMessage := c.Bool("no-start-message")
	noFilter := c.Bool("no-filter")
	cveFilter := c.Bool("enable-cve-filter")
	debug := c.Bool("debug")
	iv := c.String("interval")

	if os.Getenv("INTERVAL") != "" {
		iv = os.Getenv("INTERVAL")
	}
	if os.Getenv("NO_FILTER") != "" {
		noFilter = true
	}
	if os.Getenv("NO_START_MESSAGE") != "" {
		noStartMessage = true
	}
	if os.Getenv("ENABLE_CVE_FILTER") == "false" {
		cveFilter = false
	}

	log.Infof("config: INTERVAL=%s, NO_FILTER=%v, NO_START_MESSAGE=%v, ENABLE_CVE_FILTER=%v",
		iv, noFilter, noStartMessage, cveFilter)

	interval, err := time.ParseDuration(iv)
	if err != nil {
		return err
	}
	if interval.Minutes() < 1 && !debug {
		return fmt.Errorf("interval is too small, at least 1m")
	}

	drv, err := entSql.Open("sqlite3", "file:vuln_v2.sqlite3?cache=shared&_pragma=foreign_keys(1)")
	if err != nil {
		return errors.Wrap(err, "failed opening connection to sqlite")
	}
	db := drv.DB()
	db.SetMaxOpenConns(1)
	dbClient := ent.NewClient(ent.Driver(drv))

	defer dbClient.Close()
	if err := dbClient.Schema.Create(ctx, migrate.WithDropIndex(true), migrate.WithDropColumn(true)); err != nil {
		return errors.Wrap(err, "failed creating schema resources")
	}

	log.Infof("initialize local database..")
	// 抓取前3页作为基准漏洞数据
	eg, initCtx := errgroup.WithContext(ctx)
	eg.SetLimit(len(grabbers))
	for _, grabber := range grabbers {
		grabber := grabber
		eg.Go(func() error {
			return initData(initCtx, dbClient, grabber)
		})
	}
	err = eg.Wait()
	if err != nil {
		return errors.Wrap(err, "init data")
	}
	log.Infof("grabber finished successfully")

	localCount, err := dbClient.VulnInformation.Query().Count(ctx)
	if err != nil {
		return err
	}
	log.Infof("system init finished, local database has %d vulns", localCount)
	if !noStartMessage {
		providers := make([]*grab.Provider, 0, 3)
		for _, p := range grabbers {
			providers = append(providers, p.ProviderInfo())
		}
		msg := push.InitialMsg{
			Version:   Version,
			VulnCount: localCount,
			Interval:  interval.String(),
			Provider:  providers,
		}
		md := push.RenderInitialMsg(&msg)
		if err := pusher.PushMarkdown("WatchVuln 初始化完成", md); err != nil {
			return err
		}
	}

	log.Infof("ticking every %s", interval)

	defer func() {
		if err = pusher.PushText("注意: WatchVuln 进程退出"); err != nil {
			log.Error(err)
		}
		time.Sleep(time.Second)
	}()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		log.Infof("next checking at %s\n", time.Now().Add(interval).Format("2006-01-02 15:04:05"))

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			hour := time.Now().Hour()
			if hour >= 0 && hour < 7 {
				// we must sleep in this time
				log.Infof("sleeping..")
				continue
			}

			vulns, err := collectUpdate(ctx, dbClient, grabbers)
			if err != nil {
				log.Errorf("failed to get updates, %s", err)
				continue
			}
			log.Infof("found %d new vulns in this ticking", len(vulns))
			for _, v := range vulns {
				if noFilter || v.Creator.IsValuable(v) {
					dbVuln, err := dbClient.VulnInformation.Query().Where(vulninformation.Key(v.UniqueKey)).First(ctx)
					if err != nil {
						log.Errorf("failed to query %s from db %s", v.UniqueKey, err)
						continue
					}
					if dbVuln.Pushed {
						log.Infof("%s has been pushed, skipped", v)
						continue
					}
					if v.CVE != "" && cveFilter {
						// 同一个 cve 已经有其它源推送过了
						others, err := dbClient.VulnInformation.Query().
							Where(vulninformation.And(vulninformation.Cve(v.CVE), vulninformation.Pushed(true))).All(ctx)
						if err != nil {
							log.Errorf("failed to query %s from db %s", v.UniqueKey, err)
							continue
						}
						if len(others) != 0 {
							ids := make([]string, 0, len(others))
							for _, o := range others {
								ids = append(ids, o.Key)
							}
							log.Infof("found new cve but other source has already pushed, others: %v", ids)
							continue
						}
					}
					_, err = dbVuln.Update().SetPushed(true).Save(ctx)
					if err != nil {
						log.Errorf("failed to save pushed %s status, %s", v.UniqueKey, err)
						continue
					}
					log.Infof("Pushing %s", v)
					err = pusher.PushMarkdown(v.Title, push.RenderVulnInfo(v))
					if err != nil {
						log.Errorf("send dingding msg error, %s", err)
						break
					}
				}
			}
		}
	}
}

func initSources(c *cli.Context) ([]grab.Grabber, error) {
	sources := c.String("sources")
	if os.Getenv("SOURCES") != "" {
		sources = os.Getenv("SOURCES")
	}
	parts := strings.Split(sources, ",")
	var grabs []grab.Grabber
	for _, part := range parts {
		part = strings.ToLower(strings.TrimSpace(part))
		switch part {
		case "avd":
			grabs = append(grabs, grab.NewAVDCrawler())
		case "ti":
			grabs = append(grabs, grab.NewTiCrawler())
		case "oscs":
			grabs = append(grabs, grab.NewOSCSCrawler())
		case "seebug":
			grabs = append(grabs, grab.NewSeebugCrawler())
		default:
			return nil, fmt.Errorf("invalid grab source %s", part)
		}
	}
	return grabs, nil
}

func initPusher(c *cli.Context) (push.Pusher, error) {
	dingToken := c.String("dingding-access-token")
	dingSecret := c.String("dingding-sign-secret")
	wxWorkKey := c.String("wechatwork-key")
	webhook := c.String("webhook-url")
	larkToken := c.String("lark-access-token")
	larkSecret := c.String("lark-sign-secret")
	serverChanKey := c.String("serverchan-key")

	if os.Getenv("DINGDING_ACCESS_TOKEN") != "" {
		dingToken = os.Getenv("DINGDING_ACCESS_TOKEN")
	}
	if os.Getenv("DINGDING_SECRET") != "" {
		dingSecret = os.Getenv("DINGDING_SECRET")
	}
	if os.Getenv("WECHATWORK_KEY") != "" {
		wxWorkKey = os.Getenv("WECHATWORK_KEY")
	}
	if os.Getenv("WEBHOOK_URL") != "" {
		webhook = os.Getenv("WEBHOOK_URL")
	}
	if os.Getenv("LARK_ACCESS_TOKEN") != "" {
		larkToken = os.Getenv("LARK_ACCESS_TOKEN")
	}
	if os.Getenv("LARK_SECRET") != "" {
		larkSecret = os.Getenv("LARK_SECRET")
	}
	if os.Getenv("SERVERCHAN_KEY") != "" {
		serverChanKey = os.Getenv("SERVERCHAN_KEY")
	}
	var pushers []push.Pusher
	if dingToken != "" && dingSecret != "" {
		pushers = append(pushers, push.NewDingDing(dingToken, dingSecret))
	}
	if larkToken != "" && larkSecret != "" {
		pushers = append(pushers, push.NewLark(larkToken, larkSecret))
	}
	if wxWorkKey != "" {
		pushers = append(pushers, push.NewWechatWork(wxWorkKey))
	}
	if webhook != "" {
		pushers = append(pushers, push.NewWebhook(webhook))
	}
	if serverChanKey != "" {
		pushers = append(pushers, push.NewServerChan(serverChanKey))
	}
	if len(pushers) == 0 {
		msg := `
you must setup a pusher, eg: 
use dingding: %s --dt DINGDING_ACCESS_TOKEN --ds DINGDING_SECRET
use wechat:   %s --wk WECHATWORK_KEY
use API:   %s --webhook WEBHOOK_URL`
		return nil, fmt.Errorf(msg, os.Args[0], os.Args[0], os.Args[0])
	}
	return push.Multi(pushers...), nil
}
func initData(ctx context.Context, dbClient *ent.Client, grabber grab.Grabber) error {
	pageSize := 100
	source := grabber.ProviderInfo()
	total, err := grabber.GetPageCount(ctx, pageSize)
	if err != nil {
		return nil
	}
	if total == 0 {
		return fmt.Errorf("%s got unexpected zero page", source.Name)
	}
	if total > MaxPageBase {
		total = MaxPageBase
	}
	log.Infof("start grab %s, total page: %d", source.Name, total)

	eg, ctx := errgroup.WithContext(ctx)
	eg.SetLimit(total)

	for i := 1; i <= total; i++ {
		i := i
		eg.Go(func() error {
			dataChan, err := grabber.ParsePage(ctx, i, pageSize)
			if err != nil {
				return err
			}
			for data := range dataChan {
				if _, err = createOrUpdate(ctx, dbClient, source, data); err != nil {
					return errors.Wrap(err, data.String())
				}
			}
			return nil
		})
	}
	err = eg.Wait()
	if err != nil {
		return err
	}
	return nil
}

func collectUpdate(ctx context.Context, dbClient *ent.Client, grabbers []grab.Grabber) ([]*grab.VulnInfo, error) {
	pageSize := 10
	eg, ctx := errgroup.WithContext(ctx)
	eg.SetLimit(len(grabbers))

	var mu sync.Mutex
	var newVulns []*grab.VulnInfo

	for _, grabber := range grabbers {
		grabber := grabber
		eg.Go(func() error {
			source := grabber.ProviderInfo()
			pageCount, err := grabber.GetPageCount(ctx, pageSize)
			if err != nil {
				return err
			}
			if pageCount > MaxPageBase {
				pageCount = MaxPageBase
			}
			for i := 1; i <= pageCount; i++ {
				dataChan, err := grabber.ParsePage(ctx, i, pageSize)
				if err != nil {
					return err
				}
				hasNewVuln := false

				for data := range dataChan {
					isNewVuln, err := createOrUpdate(ctx, dbClient, source, data)
					if err != nil {
						return err
					}
					if isNewVuln {
						log.Infof("found new vuln: %s", data)
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
			}
			return nil
		})
	}
	err := eg.Wait()
	return newVulns, err
}

func createOrUpdate(ctx context.Context, dbClient *ent.Client, source *grab.Provider, data *grab.VulnInfo) (bool, error) {
	vuln, err := dbClient.VulnInformation.Query().
		Where(vulninformation.Key(data.UniqueKey)).
		First(ctx)
	// not exist
	if err != nil {
		data.Reason = append(data.Reason, grab.ReasonNewCreated)
		newVuln, err := dbClient.VulnInformation.
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
		log.Debugf("vuln %d created from %s %s", newVuln.ID, newVuln.Key, source.Name)
		return true, nil
	}

	// 如果一个漏洞之前是低危，后来改成了严重，这种可能也需要推送, 走一下高价值的判断逻辑
	asNewVuln := false
	if string(data.Severity) != vuln.Severity {
		log.Infof("%s from %s change severity from %s to %s", data.Title, data.From, vuln.Severity, data.Severity)
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
			log.Infof("%s from %s add new tag %s", data.Title, data.From, newTag)
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
	log.Debugf("vuln %d updated from %s %s", newVuln.ID, newVuln.Key, source.Name)
	return asNewVuln, nil
}

func signalCtx() (context.Context, func()) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	go func() {
		<-ch
		cancel()
	}()
	return ctx, cancel
}
