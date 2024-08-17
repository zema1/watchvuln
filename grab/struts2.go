package grab

import (
	"bytes"
	"context"
	"github.com/zema1/watchvuln/util"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/imroc/req/v3"
	"github.com/kataras/golog"
)

const Struts2Url = "https://cwiki.apache.org/confluence/display/WW/Security+Bulletins"

type Struts2Crawler struct {
	client *req.Client
	log    *golog.Logger
}

func NewStruts2Crawler() Grabber {
	client := util.NewHttpClient()
	client.SetCommonHeader("Referer", "https://cwiki.apache.org/")
	client.SetCommonHeader("Origin", "https://cwiki.apache.org/")
	client.SetCommonHeader("Accept-Language", "en-US,en;q=0.9")

	return &Struts2Crawler{
		log:    golog.Child("[Struts2-Security]"),
		client: client,
	}
}

func (c *Struts2Crawler) getVulnInfoFromURL(ctx context.Context, url string) (*VulnInfo, error) {
	resp, err := c.client.R().SetContext(ctx).Get(url)
	if err != nil {
		return nil, err
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(resp.Bytes()))
	if err != nil {
		return nil, err
	}

	var vuln VulnInfo

	// 提取漏洞严重性
	severityText := doc.Find("th:contains('Maximum security rating') + td").Text()
	vuln.Severity = getSeverityFromString(severityText)

	// 提取 CVE 编号
	vuln.CVE = doc.Find("th:contains('CVE Identifier') + td").Text()

	// 提取描述
	vuln.Description = doc.Find(`h2[id$='-Problem'] + p`).Contents().Text()

	vuln.Solutions = doc.Find("h2[id$='-Solution'] + p").Contents().Text()
	vuln.Tags = []string{
		doc.Find("th:contains('Impact of vulnerability') + td").Contents().Text(),
	}

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

var s2Id = regexp.MustCompile(`S2-\d{3}`)

func (c *Struts2Crawler) GetUpdate(ctx context.Context, vulnLimit int) ([]*VulnInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	resp, err := c.client.R().SetContext(ctx).Get(Struts2Url)
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
		if i >= totalNum-vulnLimit {
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
			//description := s.Find("span.smalltext").Text()
			title := linkTag.Text()
			link, _ := linkTag.Attr("href")

			// 构建完整的链接
			fullLink := "https://cwiki.apache.org" + link

			vuln, err := c.getVulnInfoFromURL(ctx, fullLink)
			if err != nil {
				c.log.Error(err)
				return
			}
			vuln.Title = title
			vuln.UniqueKey = s2Id.FindString(title)
			if vuln.UniqueKey == "" {
				c.log.Warnf("can not find unique key from %s", title)
				return
			}
			vuln.Creator = c
			vulnInfos = append(vulnInfos, vuln)
		}
	})
	c.log.Infof("got %d vulns", len(vulnInfos))

	return vulnInfos, nil
}

func (c *Struts2Crawler) ProviderInfo() *Provider {
	return &Provider{
		Name:        "Struts2",
		DisplayName: "Apache Struts2 Security Bulletins",
		Link:        Struts2Url,
	}
}

func (c *Struts2Crawler) IsValuable(info *VulnInfo) bool {
	return info.Severity == High || info.Severity == Critical
}
