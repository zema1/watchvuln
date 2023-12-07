package grab

import (
	"bytes"
	"context"
	"github.com/PuerkitoBio/goquery"
	"github.com/imroc/req/v3"
	"github.com/kataras/golog"
	"strings"
	"time"
)

const ConfluenceUrl = "https://cwiki.apache.org/confluence/display/WW/Security+Bulletins"

type ConfluenceCrawler struct {
	client *req.Client
	log    *golog.Logger
}

func NewConfluenceCrawler() Grabber {
	client := NewHttpClient()
	client.SetCommonHeader("Referer", "https://cwiki.apache.org/")
	client.SetCommonHeader("Origin", "https://cwiki.apache.org/")
	client.SetCommonHeader("Accept-Language", "en-US,en;q=0.9")

	return &ConfluenceCrawler{
		log:    golog.Child("[Confluence-Security]"),
		client: client,
	}
}

func (c *ConfluenceCrawler) getVulnInfoFromURL(ctx context.Context, url string) (*VulnInfo, error) {
	resp, err := c.client.R().SetContext(ctx).Get(url)
	if err != nil {
		return nil, err
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(resp.Bytes()))
	if err != nil {
		return nil, err
	}

	var vuln VulnInfo

	// 提取漏洞描述
	vuln.Description = doc.Find("#S2049-Problem").Next().Text()

	// 提取漏洞严重性
	severityText := doc.Find("th:contains('Maximum security rating') + td").Text()
	vuln.Severity = getSeverityFromString(severityText)

	// 提取 CVE 编号
	vuln.CVE = doc.Find("th:contains('CVE Identifier') + td").Text()

	// 提取其他信息
	vuln.Title = doc.Find("h2").First().Text()
	vuln.Solutions = doc.Find("#S2049-Solution").Next().Text()
	vuln.Disclosure = doc.Find("th:contains('Disclosure') + td").Text()

	vuln.From = url

	return &vuln, nil
}

func getSeverityFromString(severityText string) SeverityLevel {
	switch strings.ToLower(strings.TrimSpace(severityText)) {
	case "critical":
		return Critical
	case "important":
		return High
	case "moderate":
		return Medium
	case "low":
		return Low
	default:
		return Low // 默认为低危
	}
}

func (c *ConfluenceCrawler) GetUpdate(ctx context.Context, pageLimit int) ([]*VulnInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	resp, err := c.client.R().SetContext(ctx).Get(ConfluenceUrl)
	if err != nil {
		return nil, err
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(resp.Bytes()))
	if err != nil {
		return nil, err
	}

	var vulnInfos []*VulnInfo
	totalItems := doc.Find("#main-content > ul > li")
	totalNum := totalItems.Length()
	totalItems.Each(func(i int, s *goquery.Selection) {
		// 只处理最后的 pageLimit 条数据----从S2-060开始看....
		if i >= totalNum-pageLimit {
			/*
				From:
				<li><a href="/confluence/display/WW/S2-001">S2-001</a> — <span class="smalltext">Remote code exploit on form validation error</span></li>
				To
				Vuln
					title: S2-001 — Remote code exploit on form validation error
					Link:	https://cwiki.apache.org/confluence/display/WW/S2-001
			*/

			// 提取链接和描述
			linkTag := s.Find("a")
			description := s.Find("span.smalltext").Text()
			title := linkTag.Text() + " — " + description
			link, _ := linkTag.Attr("href")

			// 构建完整的链接
			fullLink := "https://cwiki.apache.org" + link

			vuln, _ := c.getVulnInfoFromURL(ctx, fullLink)
			vuln.UniqueKey = title
			vuln.Disclosure = "Official Public"
			vulnInfos = append(vulnInfos, vuln)
		}
	})

	return vulnInfos, nil
}

func (c *ConfluenceCrawler) ProviderInfo() *Provider {
	return &Provider{
		Name:        "confluence",
		DisplayName: "Apache Confluence Security Bulletins",
		Link:        ConfluenceUrl,
	}
}

func (c *ConfluenceCrawler) IsValuable(info *VulnInfo) bool {
	return info.Severity == High || info.Severity == Critical
}
