package push

import (
	"github.com/imroc/req/v3"
	"github.com/kataras/golog"
	"github.com/zema1/watchvuln/util"
)

var _ = TextPusher(&Bark{})

type Bark struct {
	url       string
	deviceKey string
	log       *golog.Logger
	client    *req.Client
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
		client:    util.NewHttpClient(),
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
	resp, err := m.client.R().SetBodyJsonMarshal(params).Post(url)
	if err != nil {
		return nil, err
	}
	return resp.ToBytes()
}
