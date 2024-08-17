package push

import (
	"github.com/kataras/golog"
	"github.com/pkg/errors"
	wxworkbot "github.com/vimsucks/wxwork-bot-go"
)

var _ = TextPusher(&WechatWork{})

const TypeWechatWork = "wechatwork"

type WechatWorkConfig struct {
	Type string `json:"type" yaml:"type"`
	Key  string `yaml:"key" json:"key"`
}

type WechatWork struct {
	client *wxworkbot.WxWorkBot
	log    *golog.Logger
}

func NewWechatWork(config *WechatWorkConfig) TextPusher {
	return &WechatWork{
		client: wxworkbot.New(config.Key),
		log:    golog.Child("[pusher-wechat-work]"),
	}
}

func (d *WechatWork) PushText(s string) error {
	// fixme: wxworkbot 不支持 text 类型
	d.log.Infof("sending text %s", s)
	msg := wxworkbot.Markdown{Content: s}
	err := d.client.Send(msg)
	if err != nil {
		return errors.Wrap(err, "wechat-work")
	}
	return nil
}

func (d *WechatWork) PushMarkdown(title, content string) error {
	d.log.Infof("sending markdown %s", title)
	msg := wxworkbot.Markdown{Content: content}
	err := d.client.Send(msg)
	if err != nil {
		return errors.Wrap(err, "wechat-work")
	}
	return nil
}
