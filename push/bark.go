package push

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/pkg/errors"

	"github.com/kataras/golog"
)

var _ = TextPusher(&Bark{})

type Bark struct {
	url       string
	deviceKey string
	log       *golog.Logger
	client    *http.Client
}

type BarkData struct {
	Title     string `json:"title"`
	Body      string `json:"body"`
	DeviceKey string `json:"device_key"`
	Badge     int    `json:"badge"`
	Group     string `json:"group"`
	Sound     string `json:"sound"`
	Icon      string `json:"icon"`
	Url       string `json:"url"`
}

func NewBark(url string, deviceKey string) TextPusher {
	return &Bark{
		url:       url,
		deviceKey: deviceKey,
		log:       golog.Child("[bark]"),
		client:    &http.Client{},
	}
}

func (m *Bark) PushText(s string) error {
	params := &BarkData{
		Title:     "WatchVuln",
		Body:      s,
		DeviceKey: m.deviceKey,
		Badge:     1,
		Group:     "Vuln",
		Sound:     "alert",
		Icon:      "",
		Url:       "",
	}
	m.log.Infof("sending text %s", s)

	resp, err := m.postJSON(m.url, params)
	if err != nil {
		return err
	}
	m.log.Infof("text response from server: %s", string(resp))
	return nil
}

func (m *Bark) PushMarkdown(title, content string) error {
	// m.log.Infof("sending markdown %s", title)

	// params := &Bark{
	// 	Title:   title,
	// 	Content: content,
	// 	Type:    "markdown",
	// }
	// resp, err := m.postJSON(m.url, params)
	// if err != nil {
	// 	return err
	// }
	// m.log.Infof("markdown response from server: %s", string(resp))
	return m.PushText(content)
}

func (m *Bark) postJSON(url string, params *BarkData) ([]byte, error) {
	postBody, _ := json.Marshal(params)
	return m.doPostRequest(url, "application/json", postBody)
}

func (m *Bark) doPostRequest(url string, contentType string, body []byte) ([]byte, error) {
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
