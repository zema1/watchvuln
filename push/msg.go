package push

import (
	"strings"
	"text/template"

	"github.com/zema1/watchvuln/grab"
)

const vulnInfoMsg = `
# {{ .Title }}

- CVE编号: {{ if .CVE }}**{{ .CVE }}**{{ else }}暂无{{ end }}
- 危害定级: **{{ .Severity }}**
- 漏洞标签: {{ range .Tags }}**{{ . }}** {{ end }}
- 披露日期: **{{ .Disclosure }}**
- 推送原因: {{ range .Reason }}{{ . }} {{ end }}
- 信息来源: [{{ .From }}]({{ .From }})

{{ if .Description }}### **漏洞描述**
{{ .Description }}{{ end }}

{{ if .Solutions }}###  **修复方案**
{{ .Solutions }}

{{ end -}}

{{ if .References }}### **参考链接**
{{ range $i, $ref := .References }}{{ inc $i }}. [{{ $ref }}]({{ $ref }})
{{ end }}
{{ end -}}

{{ if .CVE }}### **开源检索**
{{ if .GithubSearch }}{{ range $i, $ref := .GithubSearch }}{{ inc $i }}. [{{ $ref }}]({{ $ref }})
{{ end }}
{{ else }}暂未找到
{{ end -}}{{ end -}}
`

const initialMsg = `
数据初始化完成，当前版本 {{ .Version }}， 本地漏洞数量: {{ .VulnCount }}, 检查周期: {{ .Interval }} 

成功的数据源:
{{ range .Provider }}- [{{ .DisplayName }}]({{ .Link -}})
{{ end }}

失败的数据源:
{{ if .FailedProvider }}{{ range .FailedProvider }}- [{{ .DisplayName }}]({{ .Link }})
{{ end -}}{{ else}}无{{ end -}}
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

const (
	maxDescriptionLength    = 500
	maxReferenceIndexLength = 8
)

func RenderVulnInfo(v *grab.VulnInfo) string {
	var builder strings.Builder
	runeDescription := []rune(v.Description)
	if len(runeDescription) > maxDescriptionLength {
		v.Description = string(runeDescription[:maxDescriptionLength]) + "..."
	}
	if len(v.References) > maxReferenceIndexLength {
		v.References = v.References[:maxReferenceIndexLength]
	}
	v.Description = escapeMarkdown(v.Description)
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
	Version        string           `json:"version"`
	VulnCount      int              `json:"vuln_count"`
	Interval       string           `json:"interval"`
	Provider       []*grab.Provider `json:"provider"`
	FailedProvider []*grab.Provider `json:"failed_provider"`
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

// escapeMarkdown escapes the special characters in the markdown text.
// Pushing unclosed markdown tags on some IM platforms may result in formatting errors.
// Telegram push will directly report an send request error.
func escapeMarkdown(text string) string {
	replacer := strings.NewReplacer(
		"_", "\\_",
		"*", "\\*",
		"[", "\\[",
		"]", "\\]",
		"(", "\\(",
		")", "\\)",
		"~", "\\~",
		"`", "\\`",
		">", "\\>",
		"#", "\\#",
		"+", "\\+",
		"-", "\\-",
		"=", "\\=",
		"|", "\\|",
		"{", "\\{",
		"}", "\\}",
		"!", "\\!",
	)
	return replacer.Replace(text)
}
