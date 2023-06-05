package push

import (
	"fmt"
	"github.com/CatchZeng/dingtalk/pkg/dingtalk"
	"github.com/kataras/golog"
	"strings"
)

var _ = TextPusher(&DingDing{})

type DingDing struct {
	client *dingtalk.Client
	log    *golog.Logger
}

func NewDingDing(accessToken, secret string) TextPusher {
	return &DingDing{
		client: dingtalk.NewClient(accessToken, secret),
		log:    golog.Child("[pusher-dingding]"),
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

	// 特殊处理一下空行
	content = strings.ReplaceAll(content, "\n\n", "\n\n&nbsp;\n")
	msg := dingtalk.NewMarkdownMessage().SetMarkdown(title, content)
	_, resp, err := d.client.Send(msg)
	if err != nil {
		return fmt.Errorf("failed to send dingding markdown, %s %d %s", resp.ErrMsg, resp.ErrCode, err)
	}
	return err
}
