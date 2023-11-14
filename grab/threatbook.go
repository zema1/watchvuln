package grab

import (
	"bytes"
	"context"
	"github.com/PuerkitoBio/goquery"
	"github.com/imroc/req/v3"
	"github.com/kataras/golog"
	"github.com/mmcdole/gofeed"
	"net/http/cookiejar"
	"regexp"
	"strings"
)

/*ThreatBook 微步漏洞情报
- 微信公众号	微步在线研究响应中心
- 渠道		https://wechat2rss.xlab.app/feed/ac64c385ebcdb17fee8df733eb620a22b979928c.xml
- Demo		https://mp.weixin.qq.com/s?__biz=Mzg5MTc3ODY4Mw==&mid=2247503309&idx=1&sn=df183f5929cfabfebbc6d5c506bb7838&chksm=cfcaaed9f8bd27cf5a74fbb92e7ce8ceb823026094ee0ba71759913cd10f582725c322becb69&scene=58&subscene=0#rd
- 技术细节
	- 通过 CSS 选择器解析微信公众号的文本，识别出漏洞等级等，主要是用的相对定位法，如选取【危害评级】元素的随后一个元素
	- UniqueKey是用的是微步的编号，例如：XVE-2023-32221
	- CVE 编号是在【漏洞概况】中，用正则抓取的
	- Tag

- 已知问题
	- 有时候会被微信反爬，只获取得到 title

*/

type ThreatBookCrawler struct {
	client *req.Client
	log    *golog.Logger
}

func NewThreatBookCrawler() Grabber {
	client := wrapApiClient(NewHttpClient())
	client.SetCommonHeader("Referer", "https://mp.weixin.qq.com/")
	client.SetCommonHeader("Origin", "https://mp.weixin.qq.com/")

	return &ThreatBookCrawler{
		log:    golog.Child("[ThreatBook-Vuln]"),
		client: client,
	}
}

func (t *ThreatBookCrawler) getVulnInfoFromFeed(ctx context.Context, rss *gofeed.Item) (*VulnInfo, error) {
	vulnLink := rss.Link
	resp, err := t.client.R().SetContext(ctx).Get(vulnLink)
	if err != nil {
		return nil, err
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(resp.Bytes()))
	if err != nil {
		return nil, err
	}

	var vuln VulnInfo

	description := doc.Find(`section:contains('漏洞概况') + section`).Text()
	// 这个选择器会选择所有在包含“综合处置优先级”文本的<strong>标签后面紧跟着的<span>标签。
	//	eg: 高
	//level_1 := doc.Find("strong:contains('综合处置优先级') + span").Text()
	//	eg: 高危
	level := doc.Find("td:contains('危害评级') + td").Text()

	// trim
	vuln.Title = getTitleWithoutType(rss.Title)
	vuln.Description = strings.TrimSpace(description)
	vuln.UniqueKey = doc.Find(`td:contains('微步编号') + td`).Text()
	t.log.Debugf("UniqueKey:\t%v", vuln.UniqueKey)
	vuln.From = vulnLink

	severity := Low
	switch strings.TrimSpace(level) {
	case "低危":
		severity = Low
	case "中危":
		severity = Medium
	case "高危":
		severity = High
	case "严重":
		severity = Critical
	}
	vuln.Severity = severity

	cveIDRegexpLoose := regexp.MustCompile(`CVE-\d+-\d+`)
	cve := cveIDRegexpLoose.FindString(description)
	t.log.Debugf("Desc:\t%v", vuln.Description)
	t.log.Debugf("CVE:\t%q", cve)

	vuln.CVE = cve
	vuln.Solutions = doc.Find(`section:contains('修复方案') + section`).Text()
	vuln.Disclosure = doc.Find(`td:contains('公开程度') + td`).Text()

	vuln.Tags = []string{
		doc.Find(`td:contains('漏洞类型') + td`).Text(),
		doc.Find(`td:contains('利用条件') + td`).Text(),
		doc.Find(`td:contains('交互要求') + td`).Text(),
		doc.Find(`td:contains('威胁类型') + td`).Text(),
	}
	t.log.Debugf("Solutions:\t%v", vuln.Solutions)
	t.log.Debugf("Disclosure:\t%v", vuln.Disclosure)
	t.log.Debugf("tags:\t%v", vuln.Tags)
	t.log.Debugf("vuln: %v\n", vuln)
	return &vuln, nil
}

func (t *ThreatBookCrawler) ProviderInfo() *Provider {
	return &Provider{
		Name:        "threatbook",
		DisplayName: "微步在线研究响应中心-漏洞通告",
		Link:        "https://x.threatbook.com/v5/vulIntelligence",
	}
}

func (t *ThreatBookCrawler) GetUpdate(ctx context.Context, pageLimit int) ([]*VulnInfo, error) {
	fp := gofeed.NewParser()
	feed, _ := fp.ParseURL("https://wechat2rss.xlab.app/feed/ac64c385ebcdb17fee8df733eb620a22b979928c.xml")
	AllVulns := getAllVulnItems(feed)
	numOfVuln := len(AllVulns)
	t.log.Debugf("===GET %d vulns===", numOfVuln)

	// 开始判断漏洞重要性，组装漏洞信息
	var results []*VulnInfo

	for _, v := range AllVulns {
		t.log.Debugf("Parsing %v at %v", v.Title, v.Link)
		vuln, _ := t.getVulnInfoFromFeed(ctx, v)
		results = append(results, vuln)
	}

	return results, nil
}

func getAllVulnItems(feed *gofeed.Feed) []*gofeed.Item {
	/*
			1. 根据标题筛选公众号文章。微信推送文章的标题必须包含`漏洞通告`, `风险提示`，才视为漏洞信息
			2. 修改推送文章的名字。删除"漏洞通告"这类的前缀
		漏洞通告 | 金山终端安全... -> 金山终端安全...
	*/
	vulnItems := []*gofeed.Item{}

	for _, item := range feed.Items {
		title := item.Title
		if strings.Contains(title, "漏洞通告") || strings.Contains(title, "风险提示") {
			vulnItems = append(vulnItems, item)
		}
	}
	return vulnItems
}

func (t *ThreatBookCrawler) IsValuable(info *VulnInfo) bool {
	return info.Severity == High || info.Severity == Critical
}

func getTitleWithoutType(title string) string {
	title = strings.TrimLeft(title, "漏洞通告")
	title = strings.TrimLeft(title, "风险提示")
	title = strings.TrimSpace(title)
	title = strings.TrimLeft(title, "|")
	title = strings.TrimSpace(title)
	return title
}

func (t *ThreatBookCrawler) newClient() *req.Client {
	jar, _ := cookiejar.New(nil)
	client := NewHttpClient().
		SetCookieJar(jar).
		SetCommonHeader("Referer", "https://wechat2rss.xlab.app/feed/ac64c385ebcdb17fee8df733eb620a22b979928c.xml")
	return client
}
