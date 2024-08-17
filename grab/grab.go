package grab

import (
	"context"
	"fmt"
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
	UniqueKey    string        `json:"unique_key"`
	Title        string        `json:"title"`
	Description  string        `json:"description"`
	Severity     SeverityLevel `json:"severity"`
	CVE          string        `json:"cve"`
	Disclosure   string        `json:"disclosure"`
	Solutions    string        `json:"solutions"`
	GithubSearch []string      `json:"github_search"`
	References   []string      `json:"references"`
	Tags         []string      `json:"tags"`
	From         string        `json:"from"`
	Reason       []string      `json:"reason"`

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
	GetUpdate(ctx context.Context, pageLimit int) ([]*VulnInfo, error)
	IsValuable(info *VulnInfo) bool
}

func MergeUniqueString(s1 []string, s2 []string) []string {
	m := make(map[string]struct{}, len(s1)+len(s2))
	for _, s := range s1 {
		m[s] = struct{}{}
	}
	for _, s := range s2 {
		m[s] = struct{}{}
	}
	res := make([]string, 0, len(m))
	for k := range m {
		res = append(res, k)
	}
	return res
}
