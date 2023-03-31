package push

import (
	"bytes"
	"encoding/json"
	"github.com/pkg/errors"
	"io"
	"net/http"

	"github.com/kataras/golog"
)

var _ = Pusher(&Webhook{})

type Webhook struct {
	url    string
	log    *golog.Logger
	client *http.Client
}

type WebhookData struct {
	Title   string `json:"title"`
	Content string `json:"content"`
	Type    string `json:"type"`
}

func NewWebhook(url string) Pusher {
	return &Webhook{
		url:    url,
		log:    golog.Child("[webhook]"),
		client: &http.Client{},
	}
}

func (m *Webhook) PushText(s string) error {
	params := &WebhookData{
		Content: s,
		Title:   "",
		Type:    "text",
	}
	m.log.Infof("sending text %s", s)

	resp, err := m.postJSON(m.url, params)
	if err != nil {
		return err
	}
	m.log.Infof("text response from server: %s", string(resp))
	return nil
}

func (m *Webhook) PushMarkdown(title, content string) error {
	m.log.Infof("sending markdown %s", title)

	params := &WebhookData{
		Title:   title,
		Content: content,
		Type:    "markdown",
	}
	resp, err := m.postJSON(m.url, params)
	if err != nil {
		return err
	}
	m.log.Infof("markdown response from server: %s", string(resp))
	return nil
}
func (m *Webhook) postJSON(url string, params *WebhookData) ([]byte, error) {
	postBody, _ := json.Marshal(params)
	return m.doPostRequest(url, "application/json", postBody)
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
