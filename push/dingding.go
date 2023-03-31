package push

import (
	"fmt"
	"github.com/CatchZeng/dingtalk/pkg/dingtalk"
	"github.com/kataras/golog"
)

var _ = Pusher(&DingDing{})

type DingDing struct {
	client *dingtalk.Client
	log    *golog.Logger
}

func NewDingDing(accessToken, secret string) Pusher {
	return &DingDing{
		client: dingtalk.NewClient(accessToken, secret),
		log:    golog.Child("dingding"),
	}
}

func (d *DingDing) PushText(s string) error {
	d.log.Infof("sending text %s", s)
	_, resp, err := d.client.Send(dingtalk.NewTextMessage().SetContent(s))
	if err != nil {
		return fmt.Errorf("failed to send dingding text, %s %d %s", resp.ErrMsg, resp.ErrCode, err)
	}
	return err
}

func (d *DingDing) PushMarkdown(title, content string) error {
	d.log.Infof("sending markdown %s", title)
	msg := dingtalk.NewMarkdownMessage().SetMarkdown(title, content)
	_, resp, err := d.client.Send(msg)
	if err != nil {
		return fmt.Errorf("failed to send dingding markdown, %s %d %s", resp.ErrMsg, resp.ErrCode, err)
	}
	return err
}
