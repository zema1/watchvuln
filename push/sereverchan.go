package push

import (
	"fmt"
	"github.com/imroc/req/v3"
	"github.com/kataras/golog"
	"github.com/pkg/errors"
	"github.com/zema1/watchvuln/util"
)

var _ = TextPusher(&ServerChan{})

const TypeServerChan = "serverchan"

type ServerChanConfig struct {
	Type string `json:"type" yaml:"type"`
	Key  string `yaml:"key" json:"key"`
}

type ServerChan struct {
	pushUrl string
	log     *golog.Logger
	client  *req.Client
}

func NewServerChan(config *ServerChanConfig) TextPusher {
	return &ServerChan{
		pushUrl: fmt.Sprintf("https://sctapi.ftqq.com/%s.send", config.Key),
		log:     golog.Child("[pusher-server-chan]"),
		client:  util.NewHttpClient(),
	}
}

func (d *ServerChan) PushText(s string) error {
	d.log.Infof("sending text %s", s)
	err := d.send("", s)
	if err != nil {
		return errors.Wrap(err, "server-chan")
	}
	return nil
}

func (d *ServerChan) PushMarkdown(title, content string) error {
	d.log.Infof("sending markdown %s", title)
	err := d.send(title, content)
	if err != nil {
		return errors.Wrap(err, "server-chan")
	}
	return nil
}

func (d *ServerChan) send(text string, desp string) error {
	body := map[string]string{
		"text": text,
		"desp": desp,
	}
	_, err := d.client.R().SetBodyJsonMarshal(body).Post(d.pushUrl)
	return err
}
