package push

import (
	"fmt"
	"github.com/zema1/watchvuln/grab"
	"testing"
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
}
