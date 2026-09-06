package push

import (
	"encoding/json"
	"fmt"

	"github.com/go-resty/resty/v2"
	"github.com/kataras/golog"
	"github.com/pkg/errors"
)

var _ = TextPusher(&WPush{})

const TypeWPush = "wpush"

const wpushSendURL = "https://api.wpush.cn/api/v1/send"

type WPushConfig struct {
	Type      string `json:"type" yaml:"type"`
	APIKey    string `yaml:"apikey" json:"apikey"`
	Channel   string `yaml:"channel" json:"channel"`
	TopicCode string `yaml:"topic_code" json:"topic_code"`
}

type WPushMessage struct {
	APIKey    string `json:"apikey"`
	Title     string `json:"title"`
	Content   string `json:"content"`
	Channel   string `json:"channel,omitempty"`
	TopicCode string `json:"topic_code,omitempty"`
}

// WPushResponse uses *int for Code so missing/null JSON code is not treated as success (0).
type WPushResponse struct {
	Code    *int   `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data"`
}

type WPush struct {
	apiKey    string
	channel   string
	topicCode string
	log       *golog.Logger
}

func NewWPush(config *WPushConfig) TextPusher {
	return &WPush{
		apiKey:    config.APIKey,
		channel:   config.Channel,
		topicCode: config.TopicCode,
		log:       golog.Child("[pusher-wpush]"),
	}
}

func (r *WPush) Send(message WPushMessage) (response *WPushResponse, error error) {
	res := &WPushResponse{}
	message.APIKey = r.apiKey
	if message.Channel == "" {
		message.Channel = r.channel
	}
	if message.TopicCode == "" {
		message.TopicCode = r.topicCode
	}

	if len(message.APIKey) == 0 {
		return res, errors.New("invalid apikey")
	}

	result, err := resty.New().R().SetBody(message).SetHeader("Content-Type", "application/json").Post(wpushSendURL)

	if err != nil {
		return res, errors.New(fmt.Sprintf("请求失败：%s", err.Error()))
	}
	if err := parseWPushResponse(result.Body(), res); err != nil {
		return res, err
	}
	return res, nil
}

// parseWPushResponse requires an explicit JSON code === 0; HTTP status alone is not success.
func parseWPushResponse(body []byte, res *WPushResponse) error {
	err := json.Unmarshal(body, res)
	if err != nil {
		return errors.New("json 格式化数据失败")
	}
	if res.Code == nil {
		return errors.New("wpush api code missing")
	}
	if *res.Code != 0 {
		msg := res.Message
		if msg == "" {
			msg = "unknown error"
		}
		return errors.New(msg)
	}
	return nil
}

func (d *WPush) PushText(s string) error {
	d.log.Infof("sending text %s", s)
	message := WPushMessage{
		Title:   "WatchVuln",
		Content: s,
	}

	_, err := d.Send(message)
	if err != nil {
		return errors.Wrap(err, "wpush")
	}
	return nil
}

func (d *WPush) PushMarkdown(title, content string) error {
	d.log.Infof("sending markdown %s", title)
	message := WPushMessage{
		Title:   title,
		Content: content,
	}

	_, err := d.Send(message)
	if err != nil {
		return errors.Wrap(err, "wpush")
	}
	return nil
}
