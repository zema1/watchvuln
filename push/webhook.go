package push

import (
	"bytes"
	"encoding/json"
	"github.com/pkg/errors"
	"io"
	"net/http"

	"github.com/kataras/golog"
)

var _ = RawPusher(&Webhook{})

type Webhook struct {
	url    string
	log    *golog.Logger
	client *http.Client
}

func NewWebhook(url string) RawPusher {
	return &Webhook{
		url:    url,
		log:    golog.Child("[webhook]"),
		client: &http.Client{},
	}
}

func (m *Webhook) PushRaw(r *RawMessage) error {
	m.log.Infof("sending webhook data %s, %v", r.Type, r.Content)
	postBody, _ := json.Marshal(r)
	resp, err := m.doPostRequest(m.url, "application/json", postBody)
	if err != nil {
		return err
	}
	m.log.Infof("raw response from server: %s", string(resp))
	return nil
}

func (m *Webhook) doPostRequest(url string, contentType string, body []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, errors.Wrap(err, "create request")
	}

	req.Header.Set("Content-Type", contentType)

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "send request")
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body) // 使用 io.ReadAll 替代 ioutil.ReadAll。
	if err != nil {
		return nil, errors.Wrap(err, "read body")
	}
	return respBody, nil
}
