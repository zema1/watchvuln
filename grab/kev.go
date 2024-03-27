package grab

import (
	"context"
	"github.com/imroc/req/v3"
	"github.com/kataras/golog"
	"github.com/pkg/errors"
	"time"
)

const KEVUrl = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
const CVEUrl = "https://cveawg.mitre.org/api/cve/"
const PageSize = 5 //KEV每次都是返回全量数据，所以这里自己定义一下pagesize匹配原来的爬取逻辑

type KEVCrawler struct {
	client *req.Client
	log    *golog.Logger
}

func NewKEVCrawler() Grabber {
	client := NewHttpClient()
	client.SetCommonHeader("Referer", "Referer: https://www.cisa.gov/known-exploited-vulnerabilities-catalog")

	return &KEVCrawler{
		log:    golog.Child("[KEV]"),
		client: client,
	}
}

func (c *KEVCrawler) GetUpdate(ctx context.Context, pageLimit int) ([]*VulnInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var result kevResp
	_, err := c.client.R().SetContext(ctx).AddRetryCondition(func(resp *req.Response, err error) bool {
		if err != nil {
			return !errors.Is(err, context.Canceled)
		}
		if resp.StatusCode != 200 || !resp.IsSuccessState() {
			c.log.Warnf("failed to get content, msg: %s, retrying", resp.Status)
			return true
		}
		if err = resp.UnmarshalJson(&result); err != nil {
			c.log.Warnf("unmarshal json error, %s", err)
			return true
		}
		return false
	}).Get(KEVUrl)
	if err != nil {
		return nil, err
	}

	var vulnInfos []*VulnInfo
	var itemLimit = 0
	var maxCount = len(result.Vulnerabilities)
	if pageLimit*PageSize > maxCount {
		itemLimit = maxCount
	} else {
		itemLimit = pageLimit * PageSize
	}
	for i := 1; i <= itemLimit; i++ {
		var vulnInfo VulnInfo
		vuln := result.Vulnerabilities[maxCount-i]
		vulnInfo.UniqueKey = vuln.CveID + "_KEV"
		vulnInfo.Title = vuln.VulnerabilityName
		vulnInfo.Description = vuln.ShortDescription
		vulnInfo.CVE = vuln.CveID
		vulnInfo.Solutions = vuln.RequiredAction
		vulnInfo.Disclosure = vuln.DateAdded
		vulnInfo.From = vuln.Notes
		vulnInfo.Tags = []string{vuln.VendorProject, vuln.Product, "在野利用"}
		vulnInfos = append(vulnInfos, &vulnInfo)
	}

	return vulnInfos, nil

}

func (c *KEVCrawler) ProviderInfo() *Provider {
	return &Provider{
		Name:        "KEV",
		DisplayName: "Known Exploited Vulnerabilities Catalog",
		Link:        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
	}
}

func (c *KEVCrawler) IsValuable(info *VulnInfo) bool {
	return info.Severity == High || info.Severity == Critical
}

type kevResp struct {
	Title           string    `json:"title"`
	CatalogVersion  string    `json:"catalogVersion"`
	DateReleased    time.Time `json:"dateReleased"`
	Count           int       `json:"count"`
	Vulnerabilities []struct {
		CveID                      string `json:"cveID"`
		VendorProject              string `json:"vendorProject"`
		Product                    string `json:"product"`
		VulnerabilityName          string `json:"vulnerabilityName"`
		DateAdded                  string `json:"dateAdded"`
		ShortDescription           string `json:"shortDescription"`
		RequiredAction             string `json:"requiredAction"`
		DueDate                    string `json:"dueDate"`
		KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
		Notes                      string `json:"notes"`
	} `json:"vulnerabilities"`
}
