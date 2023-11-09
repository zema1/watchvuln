package grab

import (
	"bytes"
	"context"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"github.com/imroc/req/v3"
	"github.com/kataras/golog"
	"github.com/mmcdole/gofeed"
	"net/http/cookiejar"
	"strings"
)

type ThreatBookCrawler struct {
	client *req.Client
	log    *golog.Logger
}

func NewThreatBookCrawler() Grabber {
	client := wrapApiClient(NewHttpClient())
	client.SetCommonHeader("Referer", "https://ti.qianxin.com/")
	client.SetCommonHeader("Origin", "https://ti.qianxin.com")

	return &ThreatBookCrawler{
		log:    golog.Child("[ThreatBook-Vuln]"),
		client: client,
	}
}

func (a *ThreatBookCrawler) getVulnInfoFromURL(ctx context.Context, vulnLink string) (*VulnInfo, error) {
	resp, err := a.client.R().SetContext(ctx).Get(vulnLink)
	if err != nil {
		return nil, err
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(resp.Bytes()))
	if err != nil {
		return nil, err
	}

	title := doc.Find(`#activity-name`).Text()
	description := doc.Find(`#js_content > section:nth-child(3) > section`).Text()
	// 这个选择器会选择所有在包含“综合处置优先级”文本的<strong>标签后面紧跟着的<span>标签。eg: 高
	level := doc.Find("strong:contains('综合处置优先级') + span").Text()

	// trim
	title = strings.TrimSpace(title)
	description = strings.TrimSpace(description)
	level = strings.TrimSpace(level)

	//fixSteps := ""
	//level := ""
	//cveID := ""
	//disclosure := ""
	//avd := ""
	//var refs []string
	//var tags []string
	//
	return &VulnInfo{}, nil
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
	t.log.Infof("got %d vulns ", numOfVuln)

	// 开始判断漏洞重要性，组装漏洞信息
	var results []*VulnInfo

	for _, v := range AllVulns {
		t.log.Infof("Parsing %v at %v", v.Title, v.Link)
		vuln, _ := t.getVulnInfoFromURL(ctx, v.Link)
		t.log.Infof("\t%s %s", vuln.Title, v.Description)
		//results = append(results, result...)
	}

	return results, nil
}

func getAllVulnItems(feed *gofeed.Feed) []*gofeed.Item {
	// 微信推送文章的标题必须包含`漏洞通告`，才视为漏洞信息
	vulnItems := []*gofeed.Item{}

	for _, item := range feed.Items {
		if strings.Contains(item.Title, "漏洞通告") {
			vulnItems = append(vulnItems, item)
		}
	}
	return vulnItems
}

func (t *ThreatBookCrawler) parsePage(ctx context.Context, page int) ([]*VulnInfo, error) {
	u := fmt.Sprintf("https://www.seebug.org/vuldb/vulnerabilities?page=%d", page)
	resp, err := t.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, err
	}
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(resp.Bytes()))
	if err != nil {
		return nil, err
	}
	sel := doc.Find(".sebug-table tbody tr")
	count := sel.Length()
	if count == 0 {
		t.log.Errorf("invalid response\n%s", resp.Dump())
		return nil, fmt.Errorf("goquery find zero vulns")
	}

	var vulnInfo []*VulnInfo
	for i := 0; i < count; i++ {
		tds := sel.Eq(i).Find("td")
		if tds.Length() != 6 {
			return nil, fmt.Errorf("tag count does not match")
		}

		idTag := tds.Eq(0).Find("a")
		href, _ := idTag.Attr("href")
		href = strings.TrimSpace(href)
		if href != "" {
			href = "https://www.seebug.org" + href
		}
		uniqueKey := idTag.Text()
		uniqueKey = strings.TrimSpace(uniqueKey)

		disclosure := tds.Eq(1).Text()
		disclosure = strings.TrimSpace(disclosure)

		severityTitle, _ := tds.Eq(2).Find("div").Attr("data-original-title")
		severityTitle = strings.TrimSpace(severityTitle)
		var severity SeverityLevel
		severity = Low
		switch severityTitle {
		case "高危":
			severity = High
		case "中危":
			severity = Medium
		case "低危":
			severity = Low
		}

		title := tds.Eq(3).Text()
		title = strings.TrimSpace(title)

		cveId, _ := tds.Eq(4).Find("i.fa-id-card").Attr("data-original-title")
		cveId = strings.TrimSpace(cveId)
		if strings.Contains(cveId, "、") {
			cveId = strings.Split(cveId, "、")[0]
		}
		if !cveIDRegexp.MatchString(cveId) {
			cveId = ""
		}

		var tags []string
		tag, _ := tds.Eq(4).Find("i.fa-file-text-o").Attr("data-original-title")
		tag = strings.TrimSpace(tag)
		if tag == "有详情" {
			tags = append(tags, "有详情")
		}

		vulnInfo = append(vulnInfo, &VulnInfo{
			UniqueKey:   uniqueKey,
			Title:       title,
			Description: "",
			Severity:    severity,
			CVE:         cveId,
			Disclosure:  disclosure,
			References:  nil,
			Tags:        tags,
			Solutions:   "",
			From:        href,
			Creator:     t,
		})
	}
	return vulnInfo, nil
}

func (t *ThreatBookCrawler) IsValuable(info *VulnInfo) bool {
	return info.Severity == High || info.Severity == Critical
}

func (t *ThreatBookCrawler) newClient() *req.Client {
	jar, _ := cookiejar.New(nil)
	client := NewHttpClient().
		SetCookieJar(jar).
		SetCommonHeader("Referer", "https://wechat2rss.xlab.app/feed/ac64c385ebcdb17fee8df733eb620a22b979928c.xml")
	return client
}
