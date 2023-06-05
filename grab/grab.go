package grab

import (
	"context"
	"errors"
	"fmt"
	"github.com/imroc/req/v3"
	"github.com/kataras/golog"
	"time"
)

type SeverityLevel string
type ReasonType string

const (
	Low      SeverityLevel = "低危"
	Medium   SeverityLevel = "中危"
	High     SeverityLevel = "高危"
	Critical SeverityLevel = "严重"
)

const (
	ReasonNewCreated      = "漏洞创建"
	ReasonTagUpdated      = "标签更新"
	ReasonSeverityUpdated = "等级更新"
)

type VulnInfo struct {
	UniqueKey   string        `json:"unique_key"`
	Title       string        `json:"title"`
	Description string        `json:"description"`
	Severity    SeverityLevel `json:"severity"`
	CVE         string        `json:"cve"`
	Disclosure  string        `json:"disclosure"`
	Solutions   string        `json:"solutions"`
	References  []string      `json:"references"`
	Tags        []string      `json:"tags"`
	From        string        `json:"from"`
	Reason      []string      `json:"reason"`

	Creator Grabber `json:"-"`
}

func (v *VulnInfo) String() string {
	return fmt.Sprintf("%s (%s)", v.Title, v.From)
}

type Provider struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Link        string `json:"link"`
}

type Grabber interface {
	ProviderInfo() *Provider
	GetPageCount(ctx context.Context, size int) (int, error)
	ParsePage(ctx context.Context, page int, size int) (chan *VulnInfo, error)
	IsValuable(info *VulnInfo) bool
}

func NewHttpClient() *req.Client {
	client := req.C()
	client.
		SetCommonHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 Edg/112.0.1722.58").
		SetTimeout(10 * time.Second).
		SetCommonRetryCount(3).
		SetCookieJar(nil).
		SetCommonRetryInterval(func(resp *req.Response, attempt int) time.Duration {
			if errors.Is(resp.Err, context.Canceled) {
				return 0
			}
			return time.Second * 5
		}).
		SetCommonRetryHook(func(resp *req.Response, err error) {
			if err != nil {
				if !errors.Is(err, context.Canceled) {
					golog.Warnf("retrying as %s", err)
				}
			}
		}).SetCommonRetryCondition(func(resp *req.Response, err error) bool {
		if err != nil {
			return !errors.Is(err, context.Canceled)
		}
		return false
	})
	return client
}

func wrapApiClient(client *req.Client) *req.Client {
	return client.SetCommonHeaders(map[string]string{
		"Accept":             "application/json, text/plain, */*",
		"Accept-Language":    "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
		"Content-Type":       "application/json",
		"Sec-Fetch-Dest":     "empty",
		"Sec-Fetch-Mode":     "cors",
		"Sec-Fetch-Site":     "same-origin",
		"sec-ch-ua":          `"Microsoft Edge";v="111", "Not(A:Brand";v="8", "Chromium";v="111"`,
		"sec-ch-ua-mobile":   `?0`,
		"sec-ch-ua-platform": `"Windows"`,
	})
}
