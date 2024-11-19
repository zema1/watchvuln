package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/zema1/watchvuln/push"
	"gopkg.in/yaml.v3"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/zema1/watchvuln/ctrl"

	"github.com/kataras/golog"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

var log = golog.Child("[main]")
var Version = "v2.3.0"

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
			Name:    "config",
			Aliases: []string{"c"},
			Usage:   "config file path, support json or yaml",
		},
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
			Usage:    "webhook access token/url of lark",
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
			Name:     "pushplus-key",
			Aliases:  []string{"pk"},
			Usage:    "send key for push plus",
			Category: "[\x00Push Options]",
		},
		&cli.StringFlag{
			Name:     "webhook-url",
			Aliases:  []string{"webhook"},
			Usage:    "your webhook server url, ex: http://127.0.0.1:1111/webhook",
			Category: "[\x00Push Options]",
		},
		&cli.StringFlag{
			Name:     "lanxin-domain",
			Aliases:  []string{"lxd"},
			Usage:    "your lanxin server url, ex: https://apigw-example.domain",
			Category: "[\x00Push Options]",
		},
		&cli.StringFlag{
			Name:     "lanxin-hook-token",
			Aliases:  []string{"lxt"},
			Usage:    "lanxin hook token",
			Category: "[\x00Push Options]",
		},
		&cli.StringFlag{
			Name:     "lanxin-sign-secret",
			Aliases:  []string{"lxs"},
			Usage:    "sign secret of lanxin",
			Category: "[\x00Push Options]",
		},
		&cli.StringFlag{
			Name:     "bark-url",
			Aliases:  []string{"bark"},
			Usage:    "your bark server url, ex: http://127.0.0.1:1111/DeviceKey",
			Category: "[\x00Push Options]",
		},
		&cli.StringFlag{
			Name:     "telegram-bot-token",
			Aliases:  []string{"tgtk"},
			Usage:    "telegram bot token, ex: 123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
			Category: "[\x00Push Options]",
		},
		&cli.StringFlag{
			Name:     "telegram-chat-ids",
			Aliases:  []string{"tgids"},
			Usage:    "chat ids want to send on telegram, ex: 123456,4312341,123123",
			Category: "[\x00Push Options]",
		},
		&cli.StringFlag{
			Name:     "whitelist-file",
			Aliases:  []string{"wf"},
			Usage:    "specify a file that contains some keywords, vulns with these keywords will be pushed",
			Category: "[\x00Push Options]",
		},
		&cli.StringFlag{
			Name:     "blacklist-file",
			Aliases:  []string{"bf"},
			Usage:    "specify a file that contains some keywords, vulns with these products will NOT be pushed",
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
			Value:    "avd,nox,oscs,threatbook,seebug,struts2,kev,venustech",
			Category: "[Launch Options]",
		},
		&cli.StringFlag{
			Name:     "interval",
			Aliases:  []string{"i"},
			Usage:    "checking every [interval], supported format like 30s, 30m, 1h",
			Value:    "30m",
			Category: "[Launch Options]",
		},
		&cli.StringFlag{
			Name:     "proxy",
			Aliases:  []string{"x"},
			Usage:    "set request proxy, support socks5://xxx or http(s)://",
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
			Name:     "diff",
			Usage:    "skip init vuln db, push new vulns then exit",
			Category: "[Launch Options]",
		},
		&cli.BoolFlag{
			Name:     "insecure",
			Aliases:  []string{"k"},
			Usage:    "allow insecure server connections when using SSL/TLS",
			Category: "[Other Options]",
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

	var config *ctrl.WatchVulnAppConfig
	var err error
	if c.String("config") != "" {
		config, err = initConfigFromFile(c)
	} else {
		config, err = initConfigFromCli(c)
	}
	if err != nil {
		return errors.Wrap(err, "failed to init config")
	}

	app, err := ctrl.NewApp(config)
	if err != nil {
		return errors.Wrap(err, "failed to create app")
	}
	defer app.Close()
	if err = app.Run(ctx); err != nil {
		return errors.Wrap(err, "failed to run app")
	}
	return nil
}

func initConfigFromFile(c *cli.Context) (*ctrl.WatchVulnAppConfig, error) {
	configFile := c.String("config")
	if configFile == "" {
		return nil, fmt.Errorf("config file is required")
	}
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	var config ctrl.WatchVulnAppConfig
	if strings.HasSuffix(configFile, ".json") {
		err = json.Unmarshal(data, &config)
	}
	if strings.HasSuffix(configFile, ".yaml") || strings.HasSuffix(configFile, ".yml") {
		err = yaml.Unmarshal(data, &config)
	}
	if err != nil {
		return nil, err
	}
	config.IntervalParsed, err = time.ParseDuration(config.Interval)
	if err != nil {
		return nil, err
	}
	if config.IntervalParsed.Minutes() < 1 && !c.Bool("debug") {
		return nil, fmt.Errorf("interval is too small, at least 1m")
	}
	return &config, nil
}

func initConfigFromCli(c *cli.Context) (*ctrl.WatchVulnAppConfig, error) {
	pusher, err := initPusher(c)
	if err != nil {
		return nil, err
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
	proxy := c.String("proxy")
	diff := c.Bool("diff")
	whitelistFile := c.String("whitelist-file")
	blacklistFile := c.String("blacklist-file")
	insecure := c.Bool("insecure")

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
	if os.Getenv("DIFF") != "" {
		diff = true
	}
	if os.Getenv("DB_CONN") != "" {
		db = os.Getenv("DB_CONN")
	}
	if proxy != "" {
		must(os.Setenv("HTTP_PROXY", proxy))
		must(os.Setenv("HTTPS_PROXY", proxy))
	}
	if os.Getenv("HTTPS_PROXY") != "" {
		must(os.Setenv("HTTP_PROXY", os.Getenv("HTTPS_PROXY")))
	}

	if insecure {
		// 这个环境变量仅内部使用，go 本身并不支持
		must(os.Setenv("GO_SKIP_TLS_CHECK", "1"))
	}

	log.Infof("config: INTERVAL=%s, NO_FILTER=%v, NO_START_MESSAGE=%v, NO_GITHUB_SEARCH=%v, ENABLE_CVE_FILTER=%v",
		iv, noFilter, noStartMessage, noGithubSearch, cveFilter)

	interval, err := time.ParseDuration(iv)
	if err != nil {
		return nil, err
	}
	if interval.Minutes() < 1 && !debug {
		return nil, fmt.Errorf("interval is too small, at least 1m")
	}

	// 白名单关键字
	if os.Getenv("WHITELIST_FILE") != "" {
		whitelistFile = os.Getenv("WHITELIST_FILE")
	}
	whiteKeywords, err := splitLines(whitelistFile)
	if err != nil {
		return nil, err
	}
	if len(whiteKeywords) != 0 {
		log.Infof("using whitelist keywords: %v", whiteKeywords)
	}

	// 黑名单关键字
	if os.Getenv("BLACKLIST_FILE") != "" {
		blacklistFile = os.Getenv("BLACKLIST_FILE")
	}
	blackKeywords, err := splitLines(blacklistFile)
	if err != nil {
		return nil, err
	}
	if len(blackKeywords) != 0 {
		log.Infof("using blacklist keywords: %v", blackKeywords)
	}

	config := &ctrl.WatchVulnAppConfig{
		DBConn:          db,
		Sources:         sourcesParts,
		Interval:        iv,
		IntervalParsed:  interval,
		EnableCVEFilter: &cveFilter,
		NoStartMessage:  &noStartMessage,
		NoGithubSearch:  &noGithubSearch,
		NoFilter:        noFilter,
		DiffMode:        &diff,
		Version:         Version,
		WhiteKeywords:   whiteKeywords,
		BlackKeywords:   blackKeywords,
		Pusher:          pusher,
	}
	return config, nil
}

func initPusher(c *cli.Context) ([]map[string]string, error) {
	dingToken := c.String("dingding-access-token")
	dingSecret := c.String("dingding-sign-secret")
	wxWorkKey := c.String("wechatwork-key")
	webhook := c.String("webhook-url")
	lanxinDomain := c.String("lanxin-domain")
	lanxinToken := c.String("lanxin-hook-token")
	lanxinSecret := c.String("lanxin-sign-secret")
	bark := c.String("bark-url")
	larkToken := c.String("lark-access-token")
	larkSecret := c.String("lark-sign-secret")
	serverChanKey := c.String("serverchan-key")
	pushPlusKey := c.String("pushplus-key")
	telegramBotTokey := c.String("telegram-bot-token")
	telegramChatIDs := c.String("telegram-chat-ids")

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
	if os.Getenv("LANXIN_DOMAIN") != "" {
		lanxinDomain = os.Getenv("LANXIN_DOMAIN")
	}
	if os.Getenv("LANXIN_TOKEN") != "" {
		lanxinToken = os.Getenv("LANXIN_TOKEN")
	}
	if os.Getenv("LANXIN_SECRET") != "" {
		lanxinSecret = os.Getenv("LANXIN_SECRET")
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
	if os.Getenv("PUSHPLUS_KEY") != "" {
		pushPlusKey = os.Getenv("PUSHPLUS_KEY")
	}
	if os.Getenv("TELEGRAM_BOT_TOKEN") != "" {
		telegramBotTokey = os.Getenv("TELEGRAM_BOT_TOKEN")
	}
	if os.Getenv("TELEGRAM_CHAT_IDS") != "" {
		telegramChatIDs = os.Getenv("TELEGRAM_CHAT_IDS")
	}

	var pusherConfig []any
	if dingToken != "" && dingSecret != "" {
		pusherConfig = append(pusherConfig, &push.DingDingConfig{
			Type:        push.TypeDingDing,
			AccessToken: dingToken,
			SignSecret:  dingSecret,
		})
	}
	if wxWorkKey != "" {
		pusherConfig = append(pusherConfig, &push.WechatWorkConfig{
			Type: push.TypeWechatWork,
			Key:  wxWorkKey,
		})
	}
	if webhook != "" {
		pusherConfig = append(pusherConfig, &push.WebhookConfig{
			Type: push.TypeWebhook,
			URL:  webhook,
		})
	}
	if lanxinDomain != "" && lanxinToken != "" && lanxinSecret != "" {
		pusherConfig = append(pusherConfig, &push.LanxinConfig{
			Type:        push.TypeLanxin,
			Domain:      lanxinDomain,
			AccessToken: lanxinToken,
			SignSecret:  lanxinSecret,
		})
	}
	if bark != "" {
		pusherConfig = append(pusherConfig, &push.BarkConfig{
			Type: push.TypeBark,
			URL:  bark,
		})
	}
	if larkToken != "" && larkSecret != "" {
		pusherConfig = append(pusherConfig, &push.LarkConfig{
			Type:        push.TypeLark,
			AccessToken: larkToken,
			SignSecret:  larkSecret,
		})
	}
	if serverChanKey != "" {
		pusherConfig = append(pusherConfig, &push.ServerChanConfig{
			Type: push.TypeServerChan,
			Key:  serverChanKey,
		})
	}
	if pushPlusKey != "" {
		pusherConfig = append(pusherConfig, &push.PushPlusConfig{
			Type:  push.TypePushPlus,
			Token: pushPlusKey,
		})
	}
	if telegramBotTokey != "" && telegramChatIDs != "" {
		pusherConfig = append(pusherConfig, &push.TelegramConfig{
			Type:     push.TypeTelegram,
			BotToken: telegramBotTokey,
			ChatIDs:  telegramChatIDs,
		})
	}
	data, err := json.Marshal(pusherConfig)
	if err != nil {
		return nil, err
	}
	var pusher []map[string]string
	err = json.Unmarshal(data, &pusher)
	if err != nil {
		return nil, err
	}
	return pusher, nil
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

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func splitLines(path string) ([]string, error) {
	var products []string
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		for _, p := range strings.Split(string(data), "\n") {
			p = strings.TrimSpace(p)
			if p != "" {
				products = append(products, p)
			}
		}
	}
	return products, nil
}
