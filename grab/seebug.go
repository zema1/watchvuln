package grab

import (
	"bytes"
	"context"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/eventloop"
	"github.com/imroc/req/v3"
	"github.com/kataras/golog"
	"github.com/pkg/errors"
	"github.com/zema1/watchvuln/util"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

type SeebugCrawler struct {
	client *req.Client
	log    *golog.Logger
	mu     sync.Mutex
}

func NewSeebugCrawler() Grabber {
	c := &SeebugCrawler{
		log: golog.Child("[seebug]"),
	}
	c.client = c.newClient()
	c.client.AddCommonRetryCondition(func(resp *req.Response, err error) bool {
		if err != nil {
			return !errors.Is(err, context.Canceled)
		}
		if resp.StatusCode != 200 {
			return true
		}
		return false
	}).AddCommonRetryHook(func(resp *req.Response, err error) {
		if err != nil {
			return
		}
		if resp.StatusCode != 200 {
			c.log.Warnf("computing cloud waf cookie")
			if err := c.wafBypass(resp.Request.Context()); err != nil {
				resp.Err = err
				c.log.Errorf("bypass waf error, %s", err)
			}
		}
	})
	return c
}

func (t *SeebugCrawler) ProviderInfo() *Provider {
	return &Provider{
		Name:        "seebug",
		DisplayName: "Seebug 漏洞平台",
		Link:        "https://www.seebug.org",
	}
}

func (t *SeebugCrawler) GetUpdate(ctx context.Context, pageLimit int) ([]*VulnInfo, error) {
	pageCount, err := t.getPageCount(ctx)
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
		pageResult, err := t.parsePage(ctx, i)
		if err != nil {
			return results, err
		}
		t.log.Infof("got %d vulns from page %d", len(pageResult), i)
		results = append(results, pageResult...)
	}
	return results, nil
}

func (t *SeebugCrawler) getPageCount(ctx context.Context) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	resp, err := t.client.R().SetContext(ctx).Get("https://www.seebug.org/vuldb/vulnerabilities")
	if err != nil {
		return 0, err
	}
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(resp.Bytes()))
	if err != nil {
		return 0, err
	}
	sel := doc.Find("ul.pagination li")
	if sel.Length() < 3 {
		return 0, fmt.Errorf("failed to get pagination node")
	}
	last := sel.Last().Prev()
	count := last.Text()
	c, err := strconv.Atoi(strings.TrimSpace(count))
	if err != nil {
		return 0, errors.Wrap(err, "failed to parse page count")
	}
	if c <= 0 {
		return 0, fmt.Errorf("negative page count")
	}
	return c, nil
}

func (t *SeebugCrawler) parsePage(ctx context.Context, page int) ([]*VulnInfo, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

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

func (t *SeebugCrawler) IsValuable(info *VulnInfo) bool {
	return info.Severity == High || info.Severity == Critical
}

func (t *SeebugCrawler) newClient() *req.Client {
	jar, _ := cookiejar.New(nil)
	client := util.NewHttpClient().
		SetCookieJar(jar).
		SetCommonHeader("Referer", "https://www.seebug.org/")
	return client
}

var scriptRegexp = regexp.MustCompile(`(?m)<script>(.*?)</script>`)

func (t *SeebugCrawler) wafBypass(ctx context.Context) error {
	jar, _ := cookiejar.New(nil)
	client := t.newClient().SetCookieJar(jar)

	getScriptContent := func() (*req.Response, string, error) {
		resp, err := client.NewRequest().SetContext(ctx).Get("https://www.seebug.org/")
		if err != nil {
			return nil, "", err
		}
		// get scripts content
		matches := scriptRegexp.FindStringSubmatch(resp.String())
		if len(matches) != 2 {
			return nil, "", fmt.Errorf("invalid response, %s", resp.String())
		}
		return resp, matches[1], nil
	}

	window := map[string]interface{}{
		"navigator": map[string]interface{}{
			"userAgent": t.client.Headers.Get("User-Agent"),
		},
	}
	document := map[string]interface{}{
		"cookie": "",
	}
	location := map[string]interface{}{}

	loop := eventloop.NewEventLoop()
	defer loop.StopNoWait()
	go func() {
		<-ctx.Done()
		loop.StopNoWait()
	}()

	loop.Run(func(vm *goja.Runtime) {
		globals := vm.GlobalObject()
		_ = globals.Set("window", window)
		_ = globals.Set("document", document)
		_ = globals.Set("location", location)
	})
	_, scripts, err := getScriptContent()
	if err != nil {
		return err
	}

	loop.Run(func(runtime *goja.Runtime) {
		_, err = runtime.RunScript("waf1.js", scripts)
		if err != nil {
			t.log.Error(err)
		}
	})
	if err != nil {
		return err
	}

	// got computed cookie, like __jsl_clearance_s=1682243210.209|-1|rH5ImJeO2qt0QSZPgIZw4vndVsw%3D;max-age=3600;path=/
	// insert to cookiejar
	cookies, err := t.getCookieFromDocument(document)
	if err != nil {
		return err
	}
	u, err := url.Parse("https://www.seebug.org/")
	jar.SetCookies(u, cookies)

	// resend request, get the second script
	_, scripts, err = getScriptContent()
	if err != nil {
		return nil
	}
	cookieStr := ""
	for _, cookie := range jar.Cookies(u) {
		cookieStr += fmt.Sprintf("%s=%s; ", cookie.Name, cookie.Value)
	}
	document["cookie"] = cookieStr

	loop.Run(func(runtime *goja.Runtime) {
		_, err = runtime.RunScript("waf2.js", scripts)
		if err != nil {
			t.log.Error(err)
		}
	})
	if err != nil {
		return err
	}

	cookies, err = t.getCookieFromDocument(document)
	if err != nil {
		return err
	}
	jar.SetCookies(u, cookies)
	t.client.SetCookieJar(jar)
	return ctx.Err()
}

func (t *SeebugCrawler) getCookieFromDocument(doc map[string]interface{}) ([]*http.Cookie, error) {
	cookieStr, ok := doc["cookie"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid cookie value, %+v", doc)
	}
	cookieHelper := &http.Response{
		Header: map[string][]string{"Set-Cookie": {cookieStr}},
	}
	cookies := cookieHelper.Cookies()
	return cookies, nil
}
