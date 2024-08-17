package push

import (
	"github.com/imroc/req/v3"
	"github.com/kataras/golog"
	"github.com/pkg/errors"
	"github.com/zema1/watchvuln/util"
)

var _ = RawPusher(&Webhook{})

type Webhook struct {
	url    string
	log    *golog.Logger
	client *req.Client
}

func NewWebhook(url string) RawPusher {
	return &Webhook{
		url:    url,
		log:    golog.Child("[webhook]"),
		client: util.NewHttpClient(),
	}
}

func (m *Webhook) PushRaw(r *RawMessage) error {
	m.log.Infof("sending webhook data %s, %v", r.Type, r.Content)
	resp, err := m.client.R().SetBodyJsonMarshal(r).Post(m.url)
	if err != nil {
		return errors.Wrap(err, "webhook")
	}
	m.log.Infof("raw response from server: %s", resp.String())
	return nil
}
