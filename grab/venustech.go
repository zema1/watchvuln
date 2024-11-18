package grab

import (
	"bytes"
	"context"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/imroc/req/v3"
	"github.com/kataras/golog"

	"github.com/zema1/watchvuln/util"
)

type VenustechCrawler struct {
	client *req.Client
	log    *golog.Logger
}

func (v *VenustechCrawler) ProviderInfo() *Provider {
	return &Provider{
		Name:        "venustech",
		DisplayName: "启明星辰漏洞通告",
		Link:        "https://www.venustech.com.cn/new_type/aqtg/",
	}
}

func (v *VenustechCrawler) IsValuable(info *VulnInfo) bool {
	return info.Severity == High || info.Severity == Critical
}

func (v *VenustechCrawler) GetUpdate(ctx context.Context, pageLimit int) ([]*VulnInfo, error) {
	var results []*VulnInfo

	for i := 1; i <= pageLimit; i++ {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		pageResult, err := v.parsePage(ctx, i)
		if err != nil {
			return results, err
		}
		v.log.Infof("got %d vulns from page %d", len(pageResult), i)
		results = append(results, pageResult...)
	}

	return results, nil
}

func (v *VenustechCrawler) parsePage(ctx context.Context, page int) ([]*VulnInfo, error) {
	rawURL := "https://www.venustech.com.cn/new_type/aqtg/"
	if page > 1 {
		rawURL = fmt.Sprintf("%sindex_%d.html", rawURL, page)
	}

	resp, err := v.client.R().SetContext(ctx).Get(rawURL)
	if err != nil {
		return nil, err
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(resp.Bytes()))
	if err != nil {
		return nil, err
	}

	itemsSel := doc.Find("body > div > div.wrapper.clearfloat > div.right.main-content > div > div.main-inner-bt > ul > li > a")
	itemsCnt := itemsSel.Length()
	if itemsCnt == 0 {
		v.log.Errorf("invalid response is \n%s", resp.Dump())
		return nil, fmt.Errorf("goquery find zero vulns")
	}

	results := make([]*VulnInfo, 0, itemsCnt)
	itemsSel.Each(func(i int, s *goquery.Selection) {
		// 微软月度、Oracle 季度补丁日漏洞通告不抓取
		if strings.Contains(s.Text(), "多个安全漏洞") {
			return
		}

		if href, ok := s.Attr("href"); ok {
			vulnURL := "https://www.venustech.com.cn" + href
			vulnInfo, err := v.parseSingle(ctx, vulnURL)
			if err != nil {
				v.log.Errorf("%s %s", err, vulnURL)
				return
			}
			results = append(results, vulnInfo)
		} else {
			v.log.Errorf("failed to get href")
		}
	})

	return results, nil
}

func (v *VenustechCrawler) parseSingle(ctx context.Context, vulnURL string) (*VulnInfo, error) {
	v.log.Debugf("parsing vuln %s", vulnURL)
	resp, err := v.client.R().SetContext(ctx).Get(vulnURL)
	if err != nil {
		return nil, err
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(resp.Bytes()))
	if err != nil {
		return nil, err
	}
	contentSel := doc.Find("body > div > div.wrapper.clearfloat > div.right.main-content > div > div > div.news-content.ctn")
	vulnTableSel := contentSel.Find("div > table").First()

	// 提取开头第一个表格的内容
	vulnDataSel := vulnTableSel.Find("tbody > tr > td")
	if vulnDataSel.Length() <= 0 || vulnDataSel.Length()%2 == 1 {
		return nil, fmt.Errorf("invald vuln table")
	}
	var vulnInfo VulnInfo
	for i, spaceReplacer := 0, strings.NewReplacer(" ", "", "\u00A0", ""); i < vulnDataSel.Length(); i += 2 {
		keyText := spaceReplacer.Replace(vulnDataSel.Eq(i).Text())
		valueText := strings.TrimSpace(vulnDataSel.Eq(i + 1).Text())

		switch keyText {
		case "漏洞名称":
			vulnInfo.Title = valueText
		case "CVEID":
			if strings.Contains(valueText, "CVE") {
				// 多个 CVE 取第一个
				if strings.Contains(valueText, "、") {
					vulnInfo.CVE = strings.Split(valueText, "、")[0]
				} else {
					vulnInfo.CVE = valueText
				}
			}
		case "发现时间":
			_, err = time.Parse("2006-01-02", valueText)
			if err == nil {
				vulnInfo.Disclosure = valueText
			}
		case "漏洞等级", "等级":
			vulnInfo.Severity = Low
			switch valueText {
			case "高危":
				vulnInfo.Severity = High
			case "中危":
				vulnInfo.Severity = Medium
			case "低危":
				vulnInfo.Severity = Low
			}
		default:
		}
	}

	if vulnInfo.Title == "" {
		title := strings.TrimSpace(contentSel.Find("h3").Text())
		vulnInfo.Title = strings.TrimPrefix(title, "【漏洞通告】")
	}
	// 使用文件名做为 UniqueKey
	filename := path.Base(resp.Request.URL.Path)
	ext := path.Ext(filename)
	vulnInfo.UniqueKey = strings.TrimSuffix(filename, ext) + "_venustech"
	vulnInfo.From = vulnURL
	// 提取描述内容
	vulnInfo.Description = strings.TrimSpace(vulnTableSel.NextUntil("h2").Text())
	// 提取参考链接
	contentSel.Find("div > h3").Each(func(i int, s *goquery.Selection) {
		if strings.Contains(s.Text(), "参考链接") {
			s.NextUntil("h2").Each(func(i int, s *goquery.Selection) {
				ref := strings.TrimSpace(s.Text())
				if ref != "" {
					vulnInfo.References = append(vulnInfo.References, ref)
				}
			})
		}
	})
	vulnInfo.Creator = v
	return &vulnInfo, nil
}

func NewVenustechCrawler() Grabber {
	client := util.NewHttpClient()

	return &VenustechCrawler{
		client: client,
		log:    golog.Child("[venustech]"),
	}
}
