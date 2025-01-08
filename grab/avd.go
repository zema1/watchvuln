package grab

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/imroc/req/v3"
	"github.com/kataras/golog"
	"github.com/pkg/errors"
	"github.com/zema1/watchvuln/util"
)

var (
	cveIDRegexp = regexp.MustCompile(`^CVE-\d+-\d+$`)
	pageRegexp  = regexp.MustCompile(`第 \d+ 页 / (\d+) 页 `)
)

type AVDCrawler struct {
	client          *req.Client
	log             *golog.Logger
	allocCtx        context.Context    // 用于 Chrome 实例分配
	allocCancel     context.CancelFunc // 用于清理 Chrome 实例
	browserCtx      context.Context    // 存储浏览器上下文
	token           string             // 存储当前有效的 timestamp token
	tokenExpireTime time.Time          // token 的过期时间
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

	// 创建一个新的 Chrome 实例，确保窗口可见
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", false), // 启用 GPU 加速
		chromedp.Flag("window-size", "1920,1080"),
		chromedp.Flag("start-maximized", true),
		chromedp.Flag("disable-extensions", false),   // 允许扩展
		chromedp.Flag("disable-default-apps", false), // 允许默认应用
		chromedp.Flag("no-first-run", true),          // 允许首次运行体验
		chromedp.Flag("disable-web-security", true),
		// 添加更多仿真参数
		chromedp.Flag("enable-automation", false),                       // 禁用自动化标志
		chromedp.Flag("disable-blink-features", "AutomationControlled"), // 禁用自动化控制特征
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("disable-background-networking", false),
		chromedp.Flag("enable-features", "NetworkService,NetworkServiceInProcess"),
		chromedp.Flag("disable-background-timer-throttling", true),
		chromedp.Flag("disable-backgrounding-occluded-windows", true),
		chromedp.Flag("disable-breakpad", true),
		chromedp.Flag("disable-client-side-phishing-detection", true),
		chromedp.Flag("disable-component-extensions-with-background-pages", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-ipc-flooding-protection", true),
		chromedp.Flag("disable-popup-blocking", true),
		chromedp.Flag("disable-prompt-on-repost", true),
		chromedp.Flag("disable-renderer-backgrounding", true),
		chromedp.Flag("force-color-profile", "srgb"),
		chromedp.Flag("metrics-recording-only", true),
		chromedp.Flag("password-store", "basic"),
		chromedp.Flag("use-mock-keychain", true),
		chromedp.UserAgent("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.1.0.0 Safari/537.36"),
	)

	// 创建一个持久的 Chrome 实例
	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)

	// 创建一个持久的浏览器上下文
	browserCtx, _ := chromedp.NewContext(allocCtx)

	// 启动浏览器并等待准备就绪
	if err := chromedp.Run(browserCtx); err != nil {
		panic(fmt.Sprintf("无法启动浏览器: %v", err))
	}

	crawler := &AVDCrawler{
		client:      client,
		log:         golog.Child("[aliyun-avd]"),
		allocCtx:    allocCtx,
		allocCancel: allocCancel,
		browserCtx:  browserCtx,
	}

	return crawler
}

// Close 方法用于清理资源
func (a *AVDCrawler) Close() error {
	if a.allocCancel != nil {
		a.allocCancel()
	}
	return nil
}

// 新增方法：使用无头浏览器获取带token的URL
func (a *AVDCrawler) getTokenURL(urlStr string) (string, error) {
	// 创建一个新的标签页上下文
	tabCtx, cancel := chromedp.NewContext(a.browserCtx)
	defer cancel()

	var currentURL string
	var done = make(chan bool, 1)

	// 设置监听器，监听URL变化
	chromedp.ListenTarget(tabCtx, func(ev interface{}) {
		if ev, ok := ev.(*page.EventFrameNavigated); ok {
			a.log.Debugf("导航到URL: %s", ev.Frame.URL)
			if strings.Contains(ev.Frame.URL, "timestamp__") {
				currentURL = ev.Frame.URL
				done <- true
			}
		}
	})

	// 开始导航并等待页面加载完成
	errChan := make(chan error, 1)
	go func() {
		// 注入 JavaScript 来模拟真实浏览器环境
		err := chromedp.Run(tabCtx,
			chromedp.Navigate(urlStr),
			chromedp.Evaluate(`
				// 覆盖 webdriver 标志
				Object.defineProperty(navigator, 'webdriver', {
					get: () => false,
				});
				// 添加 chrome 对象
				if (!window.chrome) {
					window.chrome = {};
					window.chrome.runtime = {};
				}
				// 添加语言和插件
				Object.defineProperty(navigator, 'languages', {
					get: () => ['zh-CN', 'zh', 'en'],
				});
				Object.defineProperty(navigator, 'plugins', {
					get: () => [1, 2, 3, 4, 5],
				});
			`, nil),
			chromedp.WaitReady("body", chromedp.ByQuery),
		)
		if err != nil {
			errChan <- err
			return
		}
		// 如果没有通过事件获取到URL，尝试获取当前页面URL
		var location string
		if err := chromedp.Run(tabCtx, chromedp.Location(&location)); err == nil && strings.Contains(location, "timestamp__") {
			currentURL = location
			done <- true
		}
	}()

	// 设置超时
	timeout := time.After(30 * time.Second)

	// 等待导航完成或超时
	select {
	case <-done:
		a.log.Debugf("成功获取token URL: %s", currentURL)
		return currentURL, nil
	case err := <-errChan:
		if err != nil && !errors.Is(err, context.Canceled) {
			return "", fmt.Errorf("导航失败: %v", err)
		}
	case <-timeout:
		return "", fmt.Errorf("导航超时")
	}

	// 检查是否获取到了带token的URL
	if !strings.Contains(currentURL, "timestamp__") {
		return "", fmt.Errorf("未获取到有效的token URL")
	}

	return currentURL, nil
}

// 新增的方法：从 URL 中提取 timestamp token
func (a *AVDCrawler) extractToken(urlStr string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	for key := range u.Query() {
		if strings.HasPrefix(key, "timestamp__") {
			return key + "=" + u.Query().Get(key)
		}
	}
	return ""
}

// 修改 getPageContent 方法
func (a *AVDCrawler) getPageContent(urlStr string) (string, error) {
	// 先用无头浏览器访问目标URL，获取带token的新URL
	a.log.Debugf("准备获取页面内容: %s", urlStr)
	newURL, err := a.getTokenURL(urlStr)
	if err != nil {
		return "", fmt.Errorf("获取token URL失败: %v", err)
	}

	// 使用HTTP客户端请求带token的URL
	a.log.Debugf("使用token请求页面: %s", newURL)
	resp, err := a.client.R().Get(newURL)
	if err != nil {
		return "", err
	}
	content := resp.String()

	if len(content) < 1000 {
		a.log.Warnf("页面内容可能不完整: %s", content)
		return "", fmt.Errorf("页面内容不完整")
	}

	return content, nil
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
	html, err := a.getPageContent(a.ProviderInfo().Link)
	if err != nil {
		return 0, err
	}
	results := pageRegexp.FindStringSubmatch(html)
	if len(results) != 2 {
		a.log.Errorf("页面内容匹配失败，内容: %s", html)
		return 0, fmt.Errorf("failed to match page count")
	}
	count, err := strconv.Atoi(results[1])
	if err != nil {
		return 0, err
	}
	a.log.Infof("总页数: %d", count)
	return count, nil
}

func (a *AVDCrawler) parsePage(ctx context.Context, page int) ([]*VulnInfo, error) {
	u := fmt.Sprintf("%s?page=%d", a.ProviderInfo().Link, page)
	html, err := a.getPageContent(u)
	if err != nil {
		return nil, err
	}
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		return nil, err
	}
	sel := doc.Find("tbody > tr")
	count := sel.Length()
	if count == 0 {
		a.log.Errorf("invalid response is \n%s", html)
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
	a.log.Debugf("正在解析漏洞页面: %s", vulnLink)
	htmlContent, err := a.getPageContent(vulnLink)
	if err != nil {
		return nil, err
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlContent))
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
			// 使用 goquery 的方法来获取文本
			fixSteps = mainContent.Eq(i + 1).Text()
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
