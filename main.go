package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/signal"
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
var Version = "v0.2.0"

func main() {
	golog.Default.SetLevel("info")
	app := cli.NewApp()
	app.Name = "watchvuln"
	app.Usage = "A high valuable vulnerability watcher and pusher"
	app.Version = Version

	app.Flags = []cli.Flag{
		&cli.BoolFlag{
			Name:    "debug",
			Aliases: []string{"d"},
			Usage:   "set log level to debug, print more details",
			Value:   false,
		},
		&cli.StringFlag{
			Name:    "interval",
			Aliases: []string{"i"},
			Usage:   "checking every [interval], supported format like 30s, 30m, 1h",
			Value:   "30m",
		},
		&cli.StringFlag{
			Name:    "pusher-api",
			Aliases: []string{"api"},
			Usage:   "your http url",
		},
		&cli.StringFlag{
			Name:    "dingding-access-token",
			Aliases: []string{"dt"},
			Usage:   "access token of dingding bot",
		},
		&cli.StringFlag{
			Name:    "dingding-sign-secret",
			Aliases: []string{"ds"},
			Usage:   "sign secret of dingding bot",
		},
		&cli.StringFlag{
			Name:    "wechatwork-key",
			Aliases: []string{"wk"},
			Usage:   "wechat work webhook key",
		},
		&cli.BoolFlag{
			Name:    "no-start-message",
			Aliases: []string{"nm"},
			Usage:   "disable the hello message when server starts",
		},
		&cli.BoolFlag{
			Name:    "no-filter",
			Aliases: []string{"nf"},
			Usage:   "ignore the valuable filter and push all discovered vulns",
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
		log.Fatal(err)
	}
}

func Action(c *cli.Context) error {
	ctx, cancel := signalCtx()
	defer cancel()

	pusher, err := initPusher(c)
	if err != nil {
		return err
	}

	noStartMessage := c.Bool("no-start-message")
	noFilter := c.Bool("no-filter")

	debug := c.Bool("debug")
	iv := c.String("interval")

	if os.Getenv("INTERVAL") != "" {
		iv = os.Getenv("INTERVAL")
	}
	interval, err := time.ParseDuration(iv)
	if err != nil {
		return err
	}
	if interval.Minutes() < 1 && !debug {
		return fmt.Errorf("interval is too small, at least 1m")
	}

	if os.Getenv("NO_FILTER") != "" {
		noFilter = true
	}

	drv, err := entSql.Open("sqlite3", "file:vuln_v1.sqlite3?cache=shared&_pragma=foreign_keys(1)")
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

	grabbers := []grab.Grabber{
		grab.NewAVDCrawler(),
		grab.NewTiCrawler(),
		grab.NewOSCSCrawler(),
	}

	count, err := dbClient.VulnInformation.Query().Count(ctx)
	if err != nil {
		return errors.Wrap(err, "failed creating schema resources")
	}
	log.Infof("local database has %d vulns", count)
	if count < 20000 {
		log.Infof("local data is outdated, init database")
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
	}

	// 初次启动不要推送数据, 以免长时间没运行狂发消息
	vulns, err := collectUpdate(ctx, dbClient, grabbers)
	if err != nil {
		return errors.Wrap(err, "initial collect")
	}

	localCount := dbClient.VulnInformation.Query().CountX(ctx)
	log.Infof("local database has %d vulns", localCount)
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

	log.Infof("system init finished, found %d new vulns (skip pushing)", len(vulns))
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

			vulns, err = collectUpdate(ctx, dbClient, grabbers)
			if err != nil {
				log.Errorf("failed to get updates, %s", err)
				continue
			}
			log.Infof("found %d new vulns in this ticking", len(vulns))
			for _, v := range vulns {
				if noFilter || v.Creator.IsValuable(v) {
					log.Infof("publishing new vuln %s", v)
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

func initPusher(c *cli.Context) (push.Pusher, error) {
	dingToken := c.String("dingding-access-token")
	dingSecret := c.String("dingding-sign-secret")
	wxWorkKey := c.String("wechatwork-key")
	pusherApi := c.String("pusher-api")

	if os.Getenv("DINGDING_ACCESS_TOKEN") != "" {
		dingToken = os.Getenv("DINGDING_ACCESS_TOKEN")
	}
	if os.Getenv("DINGDING_SECRET") != "" {
		dingSecret = os.Getenv("DINGDING_SECRET")
	}
	if os.Getenv("WECHATWORK_KEY") != "" {
		wxWorkKey = os.Getenv("WECHATWORK_KEY")
	}
	if os.Getenv("PUSHER_API") != "" {
		pusherApi = os.Getenv("PUSHER_API")
	}

	var pushers []push.Pusher
	if dingToken != "" && dingSecret != "" {
		pushers = append(pushers, push.NewDingDing(dingToken, dingSecret))
	}
	if wxWorkKey != "" {
		pushers = append(pushers, push.NewWechatWork(wxWorkKey))
	}
	if pusherApi != "" {
		pushers = append(pushers, push.NewPusher(pusherApi))
	}
	if len(pushers) == 0 {
		msg := `
you must setup a pusher, eg: 
use dingding: %s --dt DINGDING_ACCESS_TOKEN --ds DINGDING_SECRET
use wechat:   %s --wk WECHATWORK_KEY
use API:   %s --api PUSHER_API`
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
	log.Infof("%s total page: %d", source.Name, total)

	eg, ctx := errgroup.WithContext(ctx)
	eg.SetLimit(20)

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
			SetTags(data.Tags).
			SetFrom(data.From).
			Save(ctx)
		if err != nil {
			return false, err
		}
		log.Debugf("vuln %d created from %s %s", newVuln.ID, newVuln.Key, source.Name)
		return true, nil
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
	return false, nil
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
