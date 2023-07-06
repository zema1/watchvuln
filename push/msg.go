package push

import (
	"github.com/zema1/watchvuln/grab"
	"strings"
	"text/template"
)

const vulnInfoMsg = `
# {{ .Title }}

- CVE编号: **{{ .CVE }}**
- 危害定级: **{{ .Severity }}**
- 漏洞标签: {{ range .Tags }}**{{ . }}** {{ end }}
- 披露日期: **{{ .Disclosure }}**
- 信息来源: [{{ .From }}]({{ .From }})
- 推送原因: {{ range .Reason }}{{ . }} {{ end }}

### **漏洞描述**
{{ .Description }}

{{ if and .CVE }}### **开源检索**
{{ if .GithubSearch }}{{ range $i, $ref := .GithubSearch }}{{ inc $i }}. [{{ $ref }}]({{ $ref }})
{{ end }}
{{else}}暂无

{{ end }}{{ end -}}

### **参考链接**
{{ range $i, $ref := .References }}{{ inc $i }}. [{{ $ref }}]({{ $ref }})
{{ end }}
`

const initialMsg = `
数据初始化完成，当前版本 {{ .Version }}， 本地漏洞数量: {{ .VulnCount }}, 检查周期: {{ .Interval }} 
启用的数据源:

{{ range .Provider }}
- [{{ .DisplayName }}]({{ .Link -}})
{{- end }}
`

var (
	funcMap = template.FuncMap{
		// The name "inc" is what the function will be called in the template text.
		"inc": func(i int) int {
			return i + 1
		},
	}

	vulnInfoMsgTpl = template.Must(template.New("markdown").Funcs(funcMap).Parse(vulnInfoMsg))
	initialMsgTpl  = template.Must(template.New("markdown").Funcs(funcMap).Parse(initialMsg))
)

func RenderVulnInfo(v *grab.VulnInfo) string {
	var builder strings.Builder
	if err := vulnInfoMsgTpl.Execute(&builder, v); err != nil {
		return err.Error()
	}
	return builder.String()
}

func RenderInitialMsg(v *InitialMessage) string {
	var builder strings.Builder
	if err := initialMsgTpl.Execute(&builder, v); err != nil {
		return err.Error()
	}
	return builder.String()
}

type InitialMessage struct {
	Version   string           `json:"version"`
	VulnCount int              `json:"vuln_count"`
	Interval  string           `json:"interval"`
	Provider  []*grab.Provider `json:"provider"`
}

type TextMessage struct {
	Message string `json:"message"`
}

const (
	RawMessageTypeInitial  = "watchvuln-initial"
	RawMessageTypeText     = "watchvuln-text"
	RawMessageTypeVulnInfo = "watchvuln-vulninfo"
)

type RawMessage struct {
	Content any    `json:"content"`
	Type    string `json:"type"`
}

func NewRawInitialMessage(m *InitialMessage) *RawMessage {
	return &RawMessage{
		Content: m,
		Type:    RawMessageTypeInitial,
	}
}

func NewRawTextMessage(m string) *RawMessage {
	return &RawMessage{
		Content: &TextMessage{Message: m},
		Type:    RawMessageTypeText,
	}
}

func NewRawVulnInfoMessage(m *grab.VulnInfo) *RawMessage {
	return &RawMessage{
		Content: m,
		Type:    RawMessageTypeVulnInfo,
	}
}
