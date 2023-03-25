package grab

import (
	"bytes"
	"context"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"github.com/imroc/req/v3"
	"github.com/kataras/golog"
	"golang.org/x/net/html"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	cveIDRegexp = regexp.MustCompile(`^CVE-\d+-\d+$`)
	pageRegexp  = regexp.MustCompile(`第 \d+ 页 / (\d+) 页 `)
)

type AVDCrawler struct {
	client *req.Client
	log    *golog.Logger
}

func NewAVDCrawler() Grabber {
	client := NewHttpClient()
	return &AVDCrawler{
		client: client,
		log:    golog.Child("[aliyun-avd]"),
	}
}
func (a *AVDCrawler) SourceInfo() *SourceInfo {
	return &SourceInfo{
		Name:        "aliyun-avd",
		DisplayName: "阿里云漏洞库",
		Link:        "https://avd.aliyun.com/high-risk/list",
	}
}
func (a *AVDCrawler) GetPageCount(ctx context.Context, _ int) (int, error) {
	u := `https://avd.aliyun.com/high-risk/list`
	resp, err := a.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return 0, err
	}
	results := pageRegexp.FindStringSubmatch(resp.String())
	if len(results) != 2 {
		return 0, fmt.Errorf("failed to match page count")
	}
	return strconv.Atoi(results[1])
}

func (a *AVDCrawler) ParsePage(ctx context.Context, page, _ int) (chan *VulnInfo, error) {
	u := fmt.Sprintf("https://avd.aliyun.com/high-risk/list?page=%d", page)
	a.log.Infof("parsing page %s", u)
	resp, err := a.client.R().SetContext(ctx).Get(u)
	if err != nil {
		return nil, err
	}
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(resp.Bytes()))
	if err != nil {
		return nil, err
	}
	sel := doc.Find("tbody > tr")
	count := sel.Length()
	if count == 0 {
		return nil, fmt.Errorf("goquery find zero vulns")
	}
	a.log.Infof("page %d contains %d vulns", page, count)

	hrefs := make([]string, 0, count)
	for i := 0; i < count; i++ {
		linkSel := sel.Eq(i).Find("td > a")
		if linkSel.Length() != 1 {
			return nil, fmt.Errorf("can't find a tag")
		}

		linkTag := linkSel.Get(0)
		for _, attr := range linkTag.Attr {
			if attr.Key == "href" {
				hrefs = append(hrefs, attr.Val)
				break
			}
		}
	}

	if len(hrefs) != count {
		return nil, fmt.Errorf("can't get all href")
	}

	results := make(chan *VulnInfo, 1)
	go func() {
		defer close(results)
		for _, href := range hrefs {
			select {
			case <-ctx.Done():
				return
			default:
			}
			base, _ := url.Parse("https://avd.aliyun.com/")
			uri, err := url.ParseRequestURI(href)
			if err != nil {
				a.log.Errorf("%s", err)
				return
			}
			vulnLink := base.ResolveReference(uri).String()
			avdInfo, err := a.parseSingle(ctx, vulnLink)
			if err != nil {
				a.log.Errorf("%s %s", err, vulnLink)
				return
			}
			results <- avdInfo
		}
	}()

	return results, nil
}

func (a *AVDCrawler) IsValuable(info *VulnInfo) bool {
	return info.Severity == High || info.Severity == Critical
}

func (a *AVDCrawler) parseSingle(ctx context.Context, vulnLink string) (*VulnInfo, error) {
	a.log.Debugf("parsing vuln %s", vulnLink)
	resp, err := a.client.R().SetContext(ctx).Get(vulnLink)
	if err != nil {
		return nil, err
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(resp.Bytes()))
	if err != nil {
		return nil, err
	}

	title := ""
	description := ""
	fixSteps := ""
	level := ""
	cveID := ""
	disclosure := ""
	avd := ""
	var refs []string

	// parse avd id
	u, _ := url.Parse(vulnLink)
	avd = strings.TrimSpace(u.Query().Get("id"))

	metaSel := doc.Find(`div[class="metric"]`)
	for i := 0; i < metaSel.Length(); i++ {
		metric := metaSel.Eq(i)
		label := metric.Find(".metric-label").Text()
		value := metric.Find(".metric-value").Text()
		label = strings.TrimSpace(label)
		value = strings.TrimSpace(value)

		if strings.HasPrefix(label, "CVE") {
			cveID = value
		} else if strings.HasSuffix(label, "披露时间") {
			disclosure = value
		} else {
		}
	}

	// validate
	if !cveIDRegexp.MatchString(cveID) {
		cveID = ""
		a.log.Debugf("cve id not found in %s", vulnLink)
	}

	_, err = time.Parse("2006-01-02", disclosure)
	if err != nil {
		disclosure = ""
	}

	if cveID == "" && disclosure == "" {
		// 数据有问题，不可能两个都是空的
		return nil, fmt.Errorf("invalid vuln data")
	}

	// parse title
	header := doc.Find(`h5[class="header__title"]`)
	level = header.Find(".badge").Text()
	level = strings.TrimSpace(level)
	title = header.Find(".header__title__text").Text()
	title = strings.TrimSpace(title)

	// parse main content
	mainContent := doc.Find(`div[class="py-4 pl-4 pr-4 px-2 bg-white rounded shadow-sm"]`).Children()
	for i := 0; i < mainContent.Length(); {
		sentinel := mainContent.Eq(i).Text()
		sentinel = strings.TrimSpace(sentinel)

		if sentinel == "漏洞描述" && i+1 < mainContent.Length() {
			description = mainContent.Eq(i + 1).Find("div").Eq(0).Text()
			description = strings.TrimSpace(description)
			i += 2
		} else if sentinel == "解决建议" && i+1 < mainContent.Length() {
			if mainContent.Eq(i+1).Length() != 1 {
				i += 2
				continue
			}
			// 解决一下换行问题
			innerNode := mainContent.Eq(i + 1).Nodes[0].FirstChild
			for ; innerNode != nil; innerNode = innerNode.NextSibling {
				if innerNode.Type != html.TextNode {
					continue
				}
				t := strings.TrimSpace(innerNode.Data)
				if t != "" {
					fixSteps += t + "\n"
				}
			}
			fixSteps = strings.TrimSpace(fixSteps)
			fixSteps = strings.ReplaceAll(fixSteps, "、", ". ")
			i += 2
		} else {
			i += 1
		}
	}
	refTags := mainContent.Find(`div.reference tbody > tr a`)
	for i := 0; i < refTags.Length(); i++ {
		refText, exist := refTags.Eq(i).Attr("href")
		if !exist {
			continue
		}
		refText = strings.TrimSpace(refText)
		if strings.HasPrefix(refText, "http") {
			refs = append(refs, refText)
		}
	}
	severity := Low
	switch level {
	case "低危":
		severity = Low
	case "中危":
		severity = Medium
	case "高危":
		severity = High
	case "严重":
		severity = Critical
	}

	data := &VulnInfo{
		UniqueKey:   avd,
		Title:       title,
		Description: description,
		Severity:    severity,
		CVE:         cveID,
		Disclosure:  disclosure,
		References:  refs,
		Solutions:   fixSteps,
		From:        vulnLink,
		Creator:     a,
	}
	return data, nil
}
