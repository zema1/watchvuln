package push

import (
	"github.com/CatchZeng/dingtalk/pkg/dingtalk"
	"github.com/kataras/golog"
	"github.com/zema1/watchvuln/grab"
	"strings"
	"text/template"
)

const msgTemplate = `
# {{ .Title }} 
&nbsp;

- CVE编号: **{{ .CVE }}**
- 危害定级: **{{ .Severity }}**
- 漏洞标签: {{ range .Tags }}**{{ . }}** {{ end }}
- 披露日期: **{{ .Disclosure }}**
- 信息来源: [{{ .From }}]({{ .From }})

&nbsp;
### **漏洞描述**
{{ .Description }}

&nbsp;
### **参考链接**
{{ range $i, $ref := .References }}
{{ inc $i }}. [{{ $ref }}]({{ $ref }})
{{- end }}
`

func DingDingSend(info *grab.VulnInfo, accessToken, secret string) error {
	client := dingtalk.NewClient(accessToken, secret)

	funcMap := template.FuncMap{
		// The name "inc" is what the function will be called in the template text.
		"inc": func(i int) int {
			return i + 1
		},
	}

	tpl := template.Must(template.New("markdown").Funcs(funcMap).Parse(msgTemplate))
	var builder strings.Builder
	if err := tpl.Execute(&builder, info); err != nil {
		return err
	}
	golog.Infof("sending %s", builder.String())
	msg := dingtalk.NewMarkdownMessage().SetMarkdown(info.Title, builder.String())
	_, _, err := client.Send(msg)
	return err
}
