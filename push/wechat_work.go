package push

import (
	"github.com/kataras/golog"
	"github.com/pkg/errors"
	wxworkbot "github.com/vimsucks/wxwork-bot-go"
	"strings"
)

var _ = Pusher(&WechatWork{})

type WechatWork struct {
	client *wxworkbot.WxWorkBot
	log    *golog.Logger
}

func NewWechatWork(botKey string) Pusher {
	return &WechatWork{
		client: wxworkbot.New(botKey),
		log:    golog.Child("wechat-work"),
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
	title = strings.ReplaceAll(title, "&nbsp;", "")
	content = strings.ReplaceAll(content, "&nbsp;", "")
	msg := wxworkbot.Markdown{Content: content}
	err := d.client.Send(msg)
	if err != nil {
		return errors.Wrap(err, "wechat-work")
	}
	return nil
}
