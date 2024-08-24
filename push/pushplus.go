package push

import (
	"encoding/json"
	"fmt"

	"github.com/go-resty/resty/v2"
	"github.com/kataras/golog"
	"github.com/pkg/errors"
)

var _ = TextPusher(&PushPlus{})

const TypePushPlus = "pushplus"

type PushPlusConfig struct {
	Type  string `json:"type" yaml:"type"`
	Token string `yaml:"token" json:"token"`
}

type PushPlusMessage struct {
	Token    string `json:"token"`
	Title    string `json:"title" describe:"消息标题"`
	Content  string `json:"content" describe:"具体消息内容，根据不同template支持不同格式"`
	Template string `json:"template" describe:"发送消息模板"`
}

type PushPlusResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data string `json:"data"`
}

type PushPlus struct {
	token string
	log   *golog.Logger
}

func NewPushPlus(config *PushPlusConfig) TextPusher {
	return &PushPlus{
		token: config.Token,
		log:   golog.Child("[pusher-push-plus]"),
	}
}

func (r *PushPlus) Send(message PushPlusMessage) (response *PushPlusResponse, error error) {
	res := &PushPlusResponse{}
	message.Token = r.token

	if len(message.Token) == 0 {
		return res, errors.New("invalid token")
	}

	result, err := resty.New().R().SetBody(message).SetHeader("Content-Type", "application/json").Post("https://www.pushplus.plus/send")

	if err != nil {
		return res, errors.New(fmt.Sprintf("请求失败：%s", err.Error()))
	}
	err = json.Unmarshal(result.Body(), res)
	if err != nil {
		return res, errors.New("json 格式化数据失败")
	}
	if res.Code != 200 {
		return res, errors.New(res.Msg)
	}
	return res, nil
}

func (d *PushPlus) PushText(s string) error {
	d.log.Infof("sending text %s", s)
	message := PushPlusMessage{
		Title:    "",
		Content:  s,
		Template: "txt",
	}

	_, err := d.Send(message)
	if err != nil {
		return errors.Wrap(err, "push-plus")
	}
	return nil
}

func (d *PushPlus) PushMarkdown(title, content string) error {
	d.log.Infof("sending markdown %s", title)
	message := PushPlusMessage{
		Title:    title,
		Content:  content,
		Template: "markdown",
	}

	_, err := d.Send(message)
	if err != nil {
		return errors.Wrap(err, "push-plus")
	}
	return nil
}
