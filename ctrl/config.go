package ctrl

import (
	"encoding/json"
	"entgo.io/ent/dialect"
	"fmt"
	"github.com/kataras/golog"
	"github.com/zema1/watchvuln/push"
	"net/url"
	"os"
	"time"
)

type WatchVulnAppConfig struct {
	DBConn          string              `yaml:"db_conn" json:"db_conn"`
	Sources         []string            `yaml:"sources" json:"sources"`
	Interval        string              `yaml:"interval" json:"interval"`
	EnableCVEFilter *bool               `yaml:"enable_cve_filter" json:"enable_cve_filter"`
	NoGithubSearch  *bool               `yaml:"no_github_search" json:"no_github_search"`
	NoStartMessage  *bool               `yaml:"no_start_message" json:"no_start_message"`
	DiffMode        *bool               `yaml:"diff_mode" json:"diff_mode"`
	WhiteKeywords   []string            `yaml:"white_keywords" json:"white_keywords"`
	BlackKeywords   []string            `yaml:"black_keywords" json:"black_keywords"`
	Pusher          []map[string]string `yaml:"pusher" json:"pusher"`

	NoFilter       bool          `yaml:"-" json:"-"`
	Version        string        `yaml:"-" json:"-"`
	IntervalParsed time.Duration `json:"-" yaml:"-"`
	PushRetryCount int           `yaml:"-" json:"-"`
}

const dbExample = `
sqlite3://vuln_v3.sqlite3
mysql://user:pass@host:port/dbname
postgres://user:pass@host:port/dbname
`

func (c *WatchVulnAppConfig) Init() {
	if c.EnableCVEFilter == nil {
		t := true
		c.EnableCVEFilter = &t
	}
	if c.NoGithubSearch == nil {
		c.NoGithubSearch = new(bool)
	}
	if c.NoStartMessage == nil {
		c.NoStartMessage = new(bool)
	}
	if c.DiffMode == nil {
		c.DiffMode = new(bool)
	}
	if c.Interval == "" {
		c.Interval = "1h"
	}
	if len(c.Sources) == 0 {
		c.Sources = []string{"avd", "chaitin", "nox", "oscs", "threatbook", "seebug", "struts2", "kev", "venustech"}
	}
}

func (c *WatchVulnAppConfig) DBConnForEnt() (string, string, error) {
	u, err := url.Parse(c.DBConn)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse db_conn: %w, expected:%s", err, dbExample)
	}
	switch u.Scheme {
	case dialect.SQLite:
		query := `cache=shared&_pragma=foreign_keys(1)`
		if u.RawQuery != "" {
			query = u.RawQuery
		}
		return dialect.SQLite, fmt.Sprintf("file:%s%s?%s", u.Host, u.Path, query), nil
	case dialect.MySQL:
		path := ""
		if u.Path != "" {
			path = u.Path[1:]
		}
		query := `charset=utf8mb4&parseTime=True&loc=Local`
		if u.RawQuery != "" {
			query = u.RawQuery
		}
		return dialect.MySQL, fmt.Sprintf("%s@tcp(%s)/%s?%s", u.User.String(), u.Host, path, query), nil
	case dialect.Postgres:
		path := ""
		if u.Path != "" {
			path = u.Path[1:]
		}
		query := `sslmode=disable`
		if u.RawQuery != "" {
			query = u.RawQuery
		}
		return dialect.Postgres, fmt.Sprintf("postgresql://%s@%s/%s?%s", u.User.String(), u.Host, path, query), nil
	default:
		return "", "", fmt.Errorf("unsupported db_conn: %s, expected:%s", c.DBConn, dbExample)
	}
}

func (c *WatchVulnAppConfig) GetPusher() (push.TextPusher, push.RawPusher, error) {
	var textPusher []push.TextPusher
	var rawPusher []push.RawPusher

	for _, config := range c.Pusher {
		pushType := config["type"]

		switch pushType {
		case push.TypeDingDing:
			dingConfig := unmarshal[push.DingDingConfig](config)
			if dingConfig.AccessToken == "" || dingConfig.SignSecret == "" {
				continue
			}
			textPusher = append(textPusher, push.NewDingDing(&dingConfig))
		case push.TypeLark:
			larkConfig := unmarshal[push.LarkConfig](config)
			if larkConfig.SignSecret == "" || larkConfig.AccessToken == "" {
				continue
			}
			textPusher = append(textPusher, push.NewLark(&larkConfig))
		case push.TypeWechatWork:
			wechatConfig := unmarshal[push.WechatWorkConfig](config)
			if wechatConfig.Key == "" {
				continue
			}
			textPusher = append(textPusher, push.NewWechatWork(&wechatConfig))
		case push.TypeWebhook:
			webhookConfig := unmarshal[push.WebhookConfig](config)
			if webhookConfig.URL == "" {
				continue
			}
			rawPusher = append(rawPusher, push.NewWebhook(&webhookConfig))
		case push.TypeLanxin:
			lanxinConfig := unmarshal[push.LanxinConfig](config)
			if lanxinConfig.Domain == "" || lanxinConfig.AccessToken == "" || lanxinConfig.SignSecret == "" {
				continue
			}
			textPusher = append(textPusher, push.NewLanxin(&lanxinConfig))
		case push.TypeBark:
			barkConfig := unmarshal[push.BarkConfig](config)
			if barkConfig.URL == "" {
				continue
			}
			textPusher = append(textPusher, push.NewBark(&barkConfig))
		case push.TypeServerChan:
			serverchanConfig := unmarshal[push.ServerChanConfig](config)
			if serverchanConfig.Key == "" {
				continue
			}
			textPusher = append(textPusher, push.NewServerChan(&serverchanConfig))
		case push.TypePushPlus:
			pushplusConfig := unmarshal[push.PushPlusConfig](config)
			if pushplusConfig.Token == "" {
				continue
			}
			textPusher = append(textPusher, push.NewPushPlus(&pushplusConfig))
		case push.TypeTelegram:
			telegramConfig := unmarshal[push.TelegramConfig](config)
			if telegramConfig.BotToken == "" || telegramConfig.ChatIDs == "" {
				continue
			}
			tgPusher, err := push.NewTelegram(&telegramConfig)
			if err != nil {
				return nil, nil, fmt.Errorf("init telegram error %w", err)
			}
			textPusher = append(textPusher, tgPusher)
		case push.TypeCtInternal:
			ctInternalConfig := unmarshal[push.CtInternalConfig](config)
			if ctInternalConfig.Token == "" || ctInternalConfig.GroupChat == "" {
				continue
			}
			textPusher = append(textPusher, push.NewCtInternal(&ctInternalConfig))
		default:
			return nil, nil, fmt.Errorf("unsupported push type: %s", pushType)
		}
		golog.Infof("add pusher: %s", pushType)
	}
	if len(textPusher) == 0 && len(rawPusher) == 0 {
		msg := `
you must setup at least one pusher, eg: 
use dingding: %s --dt DINGDING_ACCESS_TOKEN --ds DINGDING_SECRET
use wechat:   %s --wk WECHATWORK_KEY
use webhook:  %s --webhook WEBHOOK_URL`
		return nil, nil, fmt.Errorf(msg, os.Args[0], os.Args[0], os.Args[0])
	}
	pusherCount := len(textPusher) + len(rawPusher)
	if pusherCount > 1 {
		golog.Infof("multi pusher detected, push retry will be disabled")
		c.PushRetryCount = 0
	} else {
		c.PushRetryCount = 2
	}
	// 固定一个推送的间隔 1s，避免 dingding 等推送过快的问题
	interval := time.Second
	return push.NewMultiTextPusherWithInterval(interval, textPusher...), push.NewMultiRawPusherWithInterval(interval, rawPusher...), nil
}

func unmarshal[T any](config map[string]string) T {
	data, _ := json.Marshal(config)
	var res T
	_ = json.Unmarshal(data, &res)
	return res
}
