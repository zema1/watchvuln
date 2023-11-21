package main

import (
	"context"
	"fmt"
	"github.com/zema1/watchvuln/ctrl"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/kataras/golog"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
	"github.com/zema1/watchvuln/push"
)

var log = golog.Child("[main]")
var Version = "v1.4.0"

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
			Name:     "bark-url",
			Aliases:  []string{"bark"},
			Usage:    "your bark server url, ex: http://127.0.0.1:1111/DeviceKey",
			Category: "[\x00Push Options]",
		},
		&cli.StringFlag{
			Name:     "db-conn",
			Aliases:  []string{"db"},
			Usage:    "database connection string",
			Value:    "sqlite3://vuln_v3.sqlite3",
			Category: "[Launch Options]",
		},
		&cli.StringFlag{
			Name:     "sources",
			Aliases:  []string{"s"},
			Usage:    "set vuln sources",
			Value:    "avd,nox,oscs,threatbook,seebug",
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
			Name:     "no-github-search",
			Aliases:  []string{"ng"},
			Usage:    "don't search github repos and pull requests for every cve vuln",
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

	textPusher, rawPusher, err := initPusher(c)
	if err != nil {
		return err
	}

	sources := c.String("sources")
	if os.Getenv("SOURCES") != "" {
		sources = os.Getenv("SOURCES")
	}
	sourcesParts := strings.Split(sources, ",")

	noStartMessage := c.Bool("no-start-message")
	noFilter := c.Bool("no-filter")
	noGithubSearch := c.Bool("no-github-search")
	cveFilter := c.Bool("enable-cve-filter")
	debug := c.Bool("debug")
	iv := c.String("interval")
	db := c.String("db")

	if os.Getenv("INTERVAL") != "" {
		iv = os.Getenv("INTERVAL")
	}
	if os.Getenv("NO_FILTER") != "" {
		noFilter = true
	}
	if os.Getenv("NO_START_MESSAGE") != "" {
		noStartMessage = true
	}
	if os.Getenv("NO_GITHUB_SEARCH") != "" {
		noGithubSearch = true
	}
	if os.Getenv("ENABLE_CVE_FILTER") == "false" {
		cveFilter = false
	}
	if os.Getenv("DB_CONN") != "" {
		db = os.Getenv("DB_CONN")
	}

	log.Infof("config: INTERVAL=%s, NO_FILTER=%v, NO_START_MESSAGE=%v, NO_GITHUB_SEARCH=%v, ENABLE_CVE_FILTER=%v",
		iv, noFilter, noStartMessage, noGithubSearch, cveFilter)

	interval, err := time.ParseDuration(iv)
	if err != nil {
		return err
	}
	if interval.Minutes() < 1 && !debug {
		return fmt.Errorf("interval is too small, at least 1m")
	}
	config := &ctrl.WatchVulnAppConfig{
		DBConn:          db,
		Sources:         sourcesParts,
		Interval:        interval,
		EnableCVEFilter: cveFilter,
		NoStartMessage:  noStartMessage,
		NoGithubSearch:  noGithubSearch,
		NoFilter:        noFilter,
		Version:         Version,
	}

	app, err := ctrl.NewApp(config, textPusher, rawPusher)
	if err != nil {
		return errors.Wrap(err, "failed to create app")
	}
	defer app.Close()
	if err = app.Run(ctx); err != nil {
		return errors.Wrap(err, "failed to run app")
	}
	return nil
}

func initPusher(c *cli.Context) (push.TextPusher, push.RawPusher, error) {
	dingToken := c.String("dingding-access-token")
	dingSecret := c.String("dingding-sign-secret")
	wxWorkKey := c.String("wechatwork-key")
	webhook := c.String("webhook-url")
	bark := c.String("bark-url")
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
	if os.Getenv("BARK_URL") != "" {
		bark = os.Getenv("BARK_URL")
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
	var textPusher []push.TextPusher
	var rawPusher []push.RawPusher
	if dingToken != "" && dingSecret != "" {
		textPusher = append(textPusher, push.NewDingDing(dingToken, dingSecret))
	}
	if larkToken != "" && larkSecret != "" {
		textPusher = append(textPusher, push.NewLark(larkToken, larkSecret))
	}
	if wxWorkKey != "" {
		textPusher = append(textPusher, push.NewWechatWork(wxWorkKey))
	}
	if webhook != "" {
		rawPusher = append(rawPusher, push.NewWebhook(webhook))
	}
	if bark != "" {
		deviceKeys := strings.Split(bark, "/")
		deviceKey := deviceKeys[len(deviceKeys)-1]
		url := strings.Replace(bark, deviceKey, "push", -1)
		textPusher = append(textPusher, push.NewBark(url, deviceKey))
	}
	if serverChanKey != "" {
		textPusher = append(textPusher, push.NewServerChan(serverChanKey))
	}
	if len(textPusher) == 0 && len(rawPusher) == 0 {
		msg := `
you must setup a pusher, eg: 
use dingding: %s --dt DINGDING_ACCESS_TOKEN --ds DINGDING_SECRET
use wechat:   %s --wk WECHATWORK_KEY
use API:   %s --webhook WEBHOOK_URL`
		return nil, nil, fmt.Errorf(msg, os.Args[0], os.Args[0], os.Args[0])
	}
	return push.MultiTextPusher(textPusher...), push.MultiRawPusher(rawPusher...), nil
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
