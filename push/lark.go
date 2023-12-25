package push

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kataras/golog"
	lark "github.com/larksuite/oapi-sdk-go/v2"
)

var _ = TextPusher(&Lark{})

type Lark struct {
	log  *golog.Logger
	bot  *lark.CustomerBot
	sign string
}

func NewLark(botKey, sign string) TextPusher {
	if !strings.HasPrefix(botKey, "http") {
		botKey = "https://open.feishu.cn/open-apis/bot/v2/hook/" + botKey
	}
	bot := lark.NewCustomerBot(botKey, sign)
	return &Lark{
		bot:  bot,
		sign: sign,
		log:  golog.Child("[pusher-lark]"),
	}
}

func (d *Lark) PushText(s string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()
	d.log.Infof("sending text %s", s)
	msg := lark.MessageText{Text: s}
	resp, err := d.bot.SendMessage(ctx, "text", msg)
	if err != nil {
		return fmt.Errorf("failed to send lark text, %s", err)
	}
	if resp.CodeError.Code != 0 {
		return fmt.Errorf("failed to send lark text, %v", resp.CodeError)
	}
	return nil
}

func (d *Lark) PushMarkdown(title, content string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	d.log.Infof("sending markdown %s", title)
	title = strings.ReplaceAll(title, "&nbsp;", "")
	content = strings.ReplaceAll(content, "&nbsp;", "")
	msg := &lark.MessageCardDiv{
		Text: &lark.MessageCardLarkMd{Content: content},
	}
	card := lark.MessageCard{
		Header: &lark.MessageCardHeader{
			Title: &lark.MessageCardPlainText{Content: title},
		},
		Elements: []lark.MessageCardElement{msg},
	}
	resp, err := d.bot.SendMessage(ctx, "interactive", card)
	if err != nil {
		return fmt.Errorf("failed to send lark markdown, %s", err)
	}
	if resp.CodeError.Code != 0 {
		return fmt.Errorf("failed to send lark markdown, %v", resp.CodeError)
	}
	return nil
}
