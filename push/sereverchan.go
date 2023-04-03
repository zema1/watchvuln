package push

import (
	"github.com/kataras/golog"
	"github.com/pkg/errors"
	serverchan "github.com/rayepeng/serverchan"
)

var _ = Pusher(&WechatWork{})

type ServerChan struct {
	client *serverchan.ServerChan
	log    *golog.Logger
}

func NewServerChan(botKey string) Pusher {
	return &ServerChan{
		client: serverchan.NewServerChan(botKey),
		log:    golog.Child("[pusher-server-chan]"),
	}
}

func (d *ServerChan) PushText(s string) error {
	// fixme: ServerChan 支持 text 类型
	d.log.Infof("sending text %s", s)
	_, err := d.client.Send("no title", s)
	if err != nil {
		return errors.Wrap(err, "server-chan")
	}
	return nil
}

func (d *ServerChan) PushMarkdown(title, content string) error {
	d.log.Infof("sending markdown %s", title)
	_, err := d.client.Send(title, content)
	if err != nil {
		return errors.Wrap(err, "server-chan")
	}
	return nil
}
