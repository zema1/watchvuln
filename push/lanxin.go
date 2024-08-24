package push

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/kataras/golog"
	"github.com/pkg/errors"
)

var _ = TextPusher(&LanXin{})

const TypeLanxin = "lanxin"

type LanxinConfig struct {
	Type        string `json:"type" yaml:"type"`
	Domain      string `yaml:"domain" json:"domain"`
	AccessToken string `yaml:"access_token" json:"access_token"`
	SignSecret  string `yaml:"sign_secret" json:"sign_secret"`
}

type LanXin struct {
	domain string
	token  string
	secret string
	log    *golog.Logger
}

func NewLanxin(config *LanxinConfig) TextPusher {
	return &LanXin{
		domain: config.Domain,
		token:  config.AccessToken,
		secret: config.SignSecret,
		log:    golog.Child("[pusher-lanxin]"),
	}
}

type MessageData struct {
	Text struct {
		Content string `json:"content"`
	} `json:"text"`
}

type LanXinMessage struct {
	Sign      string      `json:"sign"`
	Timestamp string      `json:"timestamp"`
	MsgType   string      `json:"msgType"`
	MsgData   MessageData `json:"msgData"`
}

type LanXinResponse struct {
	ErrCode int    `json:"errCode"`
	ErrMsg  string `json:"errMsg"`
	Data    struct {
		MsgID string `json:"msgId"`
	} `json:"data"`
}

func GenSign(secret string, timestamp int64) string {
	stringToSign := fmt.Sprintf("%v", timestamp) + "@" + secret
	h := hmac.New(sha256.New, []byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return signature
}

// func (m *LanXin) PushRaw(r *RawMessage) error {
// 	m.log.Infof("sending lanxin data %s, %v", r.Type, r.Content)
// 	resp, err := m.Send(r.Content.(string))
// 	if err != nil {
// 		return err
// 	}
// 	m.log.Infof("raw response from server: %s", resp.Data.MsgID)
// 	return nil
// }

func (m *LanXin) PushMarkdown(title, content string) error {
	m.log.Infof("sending markdown %s", title)
	_, err := m.Send(content)
	if err != nil {
		return errors.Wrap(err, "lanxin")
	}

	return nil
}

func (m *LanXin) PushText(s string) error {
	m.log.Infof("sending text %s", s)
	_, err := m.Send(s)
	if err != nil {
		return errors.Wrap(err, "lanxin")
	}

	return nil
}

func (m *LanXin) Send(content string) (response *LanXinResponse, error error) {
	res := &LanXinResponse{}

	if len(m.domain) == 0 {
		return res, errors.New("invalid domain")
	}

	if len(m.token) == 0 {
		return res, errors.New("invalid token")
	}

	if len(m.secret) == 0 {
		return res, errors.New("invalid secret")
	}

	url := m.domain + "/v1/bot/hook/messages/create?hook_token=" + m.token
	now := time.Now().Unix() // 获取当前时间戳
	msg := LanXinMessage{
		Sign:      GenSign(m.secret, now),
		Timestamp: strconv.FormatInt(now, 10),
		MsgType:   "text",
		MsgData: MessageData{
			Text: struct {
				Content string `json:"content"`
			}{
				Content: content,
			},
		},
	}

	payload, _ := json.Marshal(msg)
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "read body")
	}
	err = json.Unmarshal(data, res)
	if err != nil {
		return res, errors.New("json格式好数据失败")
	}
	if res.ErrCode != 0 {
		return res, errors.New(res.ErrMsg)
	}
	return res, nil
}
