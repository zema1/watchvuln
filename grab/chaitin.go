package grab

import (
	"context"
	"fmt"
	"github.com/zema1/watchvuln/util"
	"strings"
	"time"
	"unicode"

	"github.com/imroc/req/v3"
	"github.com/kataras/golog"
)

type ChaitinCrawler struct {
	client *req.Client
	log    *golog.Logger
}

func NewChaitinCrawler() Grabber {
	client := util.WrapApiClient(util.NewHttpClient())
	client.SetCommonHeader("Referer", "https://stack.chaitin.com/vuldb/index")
	client.SetCommonHeader("Origin", "https://stack.chaitin.com")

	c := &ChaitinCrawler{
		log:    golog.Child("[chaitin]"),
		client: client,
	}
	return c
}

func (t *ChaitinCrawler) ProviderInfo() *Provider {
	return &Provider{
		Name:        "chaitin",
		DisplayName: "长亭漏洞库",
		Link:        "https://stack.chaitin.com/vuldb/index",
	}
}

func (t *ChaitinCrawler) GetUpdate(ctx context.Context, pageLimit int) ([]*VulnInfo, error) {
	var results []*VulnInfo
	// CT- 为长亭漏洞库的标识
	urlTpl := "https://stack.chaitin.com/api/v2/vuln/list/?limit=15&offset=%d&search=CT-"
	for i := 0; i < pageLimit; i++ {
		t.log.Infof("get vuln from chatin page %d", i+1)
		u := fmt.Sprintf(urlTpl, i*15)
		var body ChaitinResp
		_, err := t.client.R().
			SetSuccessResult(&body).
			SetContext(ctx).
			Get(u)
		if err != nil {
			return nil, err
		}
		for _, d := range body.Data.List {
			severity := Low
			switch d.Severity {
			case "low":
				severity = Low
			case "medium":
				severity = Medium
			case "high":
				severity = High
			case "critical":
				severity = Critical
			}

			disclosureDate := d.CreatedAt.Format("2006-01-02")
			var refs []string
			if d.References != nil {
				refs = strings.Split(*d.References, "\n")
			}
			var cveId string
			if d.CveId != nil {
				cveId = *d.CveId
			}
			info := &VulnInfo{
				UniqueKey:   d.CtId,
				Title:       d.Title,
				Description: d.Summary,
				Severity:    severity,
				CVE:         cveId,
				Disclosure:  disclosureDate,
				References:  refs,
				From:        "https://stack.chaitin.com/vuldb/detail/" + d.Id,
				Creator:     t,
			}
			results = append(results, info)
		}
	}

	t.log.Infof("got %d vulns from chaitin api", len(results))
	return results, nil
}

func (t *ChaitinCrawler) IsValuable(info *VulnInfo) bool {
	if info.Severity != High && info.Severity != Critical {
		return false
	}

	if !ContainsChinese(info.Title) {
		return false
	}
	return true
}

type ChaitinResp struct {
	Msg  string `json:"msg"`
	Data struct {
		Count    int         `json:"count"`
		Next     string      `json:"next"`
		Previous interface{} `json:"previous"`
		List     []struct {
			Id             string    `json:"id"`
			Title          string    `json:"title"`
			Summary        string    `json:"summary"`
			Severity       string    `json:"severity"`
			CtId           string    `json:"ct_id"`
			CveId          *string   `json:"cve_id"`
			References     *string   `json:"references"`
			DisclosureDate *string   `json:"disclosure_date"`
			CreatedAt      time.Time `json:"created_at"`
			UpdatedAt      time.Time `json:"updated_at"`
		} `json:"list"`
	} `json:"data"`
	Code int `json:"code"`
}

func ContainsChinese(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Han, r) {
			return true
		}
	}
	return false
}
