package push

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/zema1/watchvuln/grab"
)

func TestRenderVulnInfo(t *testing.T) {
	v := &grab.VulnInfo{
		Title:        "Pipreqs 代码执行漏洞",
		CVE:          "CVE-2023-31543",
		Severity:     "高危",
		Tags:         []string{"POC公开", "技术细节公开"},
		Disclosure:   "2023-06-30",
		From:         "https://ti.qianxin.com/vulnerability",
		Reason:       []string{"created"},
		Description:  "Pipreqs 存在任意代码执行漏洞，Pipreqs中的依赖项混淆允许攻击者通过将精心设计的 PyPI 包上传到所选存储库服务器来执行任意代码。",
		GithubSearch: []string{"https://github.com/pipreqs/pipreqs/issues/1"},
		References:   []string{"https://ti.qianxin.com/blog/articles/pipreqs-code-execution-vulnerability/"},
		Solutions:    "1. 升级到最新版本\n2. 更新",
	}
	fmt.Println(RenderVulnInfo(v))
	fmt.Println("============================")
	v.GithubSearch = nil
	fmt.Println(RenderVulnInfo(v))
	fmt.Println("============================")
	v.CVE = ""
	fmt.Println(RenderVulnInfo(v))

	fmt.Println("============================")
	v.References = nil
	fmt.Println(RenderVulnInfo(v))

	fmt.Println("============================")
	v.CVE = "CVE-2023-31543"
	fmt.Println(RenderVulnInfo(v))

	fmt.Println("============================")
	v.Solutions = ""
	fmt.Println(RenderVulnInfo(v))
}

func TestEscapeMarkdown(t *testing.T) {
	testCases := []struct {
		name             string
		inputDescription string
		expected         string
	}{
		{
			name:             "escape underscores",
			inputDescription: "I Doc View。2023年11月，官方发布13.10.1_20231115版本，修复相关漏洞。",
			expected:         "I Doc View。2023年11月，官方发布13.10.1\\_20231115版本，修复相关漏洞。",
		},
		{
			name:             "escape asterisks",
			inputDescription: "This is not a *bold text",
			expected:         "This is not a \\*bold text",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := escapeMarkdown(tc.inputDescription)
			assert.Equal(t, tc.expected, result)
		})
	}
}
