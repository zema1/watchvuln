package push

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/kataras/golog"
)

type PusherAPI struct {
	url string
	log *golog.Logger
}

type Params struct {
	Title   string `json:"title"`
	Content string `json:"content"`
}

func NewPusher(url string) *PusherAPI {
	return &PusherAPI{
		url: url,
		log: golog.Child("pusherapi"),
	}
}

func (m *PusherAPI) PushText(s string) error {
	params := &Params{
		Title:   "程序异常",
		Content: s,
	}

	resp := m.postJSON(m.url, params)
	if resp == nil {
		return fmt.Errorf("failed to send text")
	}
	fmt.Println(string(resp))
	return nil
}

func (m *PusherAPI) PushMarkdown(title, content string) error {
	params := &Params{
		Title:   title,
		Content: content,
	}

	resp := m.postJSON(m.url, params)
	if resp == nil {
		return fmt.Errorf("failed to send text")
	}
	fmt.Println(string(resp))
	return nil
}
func (m *PusherAPI) postJSON(url string, params *Params) []byte {
	postBody, _ := json.Marshal(params)

	return doPostRequest(url, "application/json", postBody, m.log)
}

func doPostRequest(url string, contentType string, body []byte, log *golog.Logger) []byte {
	client := &http.Client{}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		log.Errorf("Error in creating request: %s", err)
		return nil
	}

	req.Header.Set("Content-Type", contentType)

	resp, err := client.Do(req)
	if err != nil {
		log.Errorf("Error in sending request: %s", err)
		return nil
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body) // 使用 io.ReadAll 替代 ioutil.ReadAll。
	if err != nil {
		log.Errorf("Error in reading response body: %s", err)
		return nil
	}

	return respBody
}
