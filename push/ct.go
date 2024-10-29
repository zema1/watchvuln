package push

import (
	"encoding/base64"
	"fmt"
	"github.com/imroc/req/v3"
	"github.com/kataras/golog"
	"github.com/zema1/watchvuln/util"
	"strings"
)

var _ = TextPusher(&CtInternal{})

const TypeCtInternal = "ct"

type CtInternalConfig struct {
	Token     string `yaml:"token" json:"token"`
	GroupChat string `yaml:"group_chat" json:"group_chat"`
}

type CtInternal struct {
	log    *golog.Logger
	client *req.Client
	config *CtInternalConfig
}

func NewCtInternal(config *CtInternalConfig) TextPusher {
	return &CtInternal{
		log:    golog.Child("[pusher-ct]"),
		client: util.NewHttpClient(),
		config: config,
	}
}

func (d *CtInternal) PushText(s string) error {
	return d.pushMessage(s)
}

func (d *CtInternal) PushMarkdown(title, content string) error {
	// 特殊处理一下空行
	content = strings.ReplaceAll(content, "\n\n", "\n\n&nbsp;\n")
	return d.pushMessage(content)
}

func (d *CtInternal) pushMessage(message string) error {
	shortMessage := message
	if len(shortMessage) > 50 {
		shortMessage = shortMessage[:50] + "..."
	}
	d.log.Infof("sending message %s", shortMessage)
	params := map[string]string{
		"message": message,
	}
	// 看不见我看不见我
	prefix, _ := base64.StdEncoding.DecodeString("aHR0cHM6Ly9tZXNzZW5nZXIuY2hhaXRpbi5uZXQvYXBpL3YxL2xlZ2FjeV93ZWJob29r")
	u := fmt.Sprintf("%s/%s/%s", prefix, d.config.Token, d.config.GroupChat)
	resp, err := d.client.R().SetBodyJsonMarshal(params).Post(u)
	if err != nil {
		return err
	}
	if resp.StatusCode != 201 {
		return fmt.Errorf("failed to send ct message, %d", resp.StatusCode)
	}
	return nil
}
