package grab

import (
	"bytes"
	"context"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"github.com/imroc/req/v3"
	"github.com/kataras/golog"
	"github.com/pkg/errors"
	"github.com/zema1/watchvuln/util"
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
	client := util.NewHttpClient().AddCommonRetryCondition(func(resp *req.Response, err error) bool {
		if err != nil {
			return !errors.Is(err, context.Canceled)
		}
		if resp.StatusCode != 200 {
			return true
		}
		return false
	})
	return &AVDCrawler{
		client: client,
		log:    golog.Child("[aliyun-avd]"),
	}
}
func (a *AVDCrawler) ProviderInfo() *Provider {
	return &Provider{
		Name:        "aliyun-avd",
		DisplayName: "阿里云漏洞库",
		Link:        "https://avd.aliyun.com/high-risk/list",
	}
}
func (a *AVDCrawler) GetUpdate(ctx context.Context, pageLimit int) ([]*VulnInfo, error) {
	pageCount, err := a.getPageCount(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "get page count")
	}
	if pageCount == 0 {
		return nil, fmt.Errorf("invalid page count")
	}
	if pageCount > pageLimit {
		pageCount = pageLimit
	}

	var results []*VulnInfo
	for i := 1; i <= pageCount; i++ {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}
		pageResult, err := a.parsePage(ctx, i)
		if err != nil {
			return results, err
		}
		a.log.Infof("got %d vulns from page %d", len(pageResult), i)
		results = append(results, pageResult...)
	}
	return results, nil
}

func (a *AVDCrawler) getPageCount(ctx context.Context) (int, error) {
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

func (a *AVDCrawler) parsePage(ctx context.Context, page int) ([]*VulnInfo, error) {
	u := fmt.Sprintf("https://avd.aliyun.com/high-risk/list?page=%d", page)
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
		a.log.Errorf("invalid response is \n%s", resp.Dump())
		return nil, fmt.Errorf("goquery find zero vulns")
	}

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

	results := make([]*VulnInfo, 0, count)
	for _, href := range hrefs {
		select {
		case <-ctx.Done():
			return results, nil
		default:
		}
		base, _ := url.Parse("https://avd.aliyun.com/")
		uri, err := url.ParseRequestURI(href)
		if err != nil {
			a.log.Errorf("%s", err)
			return results, nil
		}
		vulnLink := base.ResolveReference(uri).String()
		avdInfo, err := a.parseSingle(ctx, vulnLink)
		if err != nil {
			a.log.Errorf("%s %s", err, vulnLink)
			return results, nil
		}
		results = append(results, avdInfo)
	}

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
	var tags []string

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
		} else if strings.HasPrefix(label, "利用情况") {
			if value != "暂无" {
				value = strings.ReplaceAll(value, " ", "")
				tags = append(tags, value)
			}
		} else if strings.HasSuffix(label, "披露时间") {
			disclosure = value
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
		Tags:        tags,
		Creator:     a,
	}
	return data, nil
}
