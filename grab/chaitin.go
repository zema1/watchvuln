package grab

import (
	"context"
	"fmt"
	"github.com/zema1/watchvuln/util"
	"strings"
	"time"

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
	resp, err := t.client.R().
		SetContext(ctx).
		Get("https://stack.chaitin.com/api/v2/vuln/list/?limit=15&offset=0&search=CT-")
	if err != nil {
		return nil, err
	}
	fmt.Print(resp.Dump())
	var body ChaitinResp
	if err = resp.UnmarshalJson(&body); err != nil {
		return nil, err
	}
	errCount := 0
	nextReqUrl := "https://stack.chaitin.com/api/v2/vuln/list/?limit=15&offset=0&search=CT-"
	for i := 1; i <= pageLimit; i++ {
		if errCount > 5 {
			t.log.Errorf("get page %d failed more than 5 times, stop", i)
			break
		}
		// CT- 为长亭漏洞库的标识
		t.log.Infof("req url: %s", nextReqUrl)
		nextReqUrl = strings.Replace(nextReqUrl, "http://", "https://", -1)
		resp, err := t.client.R().
			SetContext(ctx).
			Get(nextReqUrl)
		if err != nil {
			t.log.Errorf("get page %d failed: %v", i, err)
			i = i - 1
			errCount++
			time.Sleep(5 * time.Second)
			continue
		}
		var body ChaitinResp
		if err = resp.UnmarshalJson(&body); err != nil {
			t.log.Errorf("unmarshal page %d failed: %v", i, err)
			errCount++
			i = i - 1
			time.Sleep(5 * time.Second)
			continue
		}
		nextReqUrl = body.Data.Next
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

			DisclosureDate := ""
			if d.DisclosureDate != nil {
				DisclosureDate = *d.DisclosureDate
			}
			info := &VulnInfo{
				UniqueKey:   d.CtId,
				Title:       d.Title,
				Description: d.Summary,
				Severity:    severity,
				CVE:         d.CtId,
				Disclosure:  DisclosureDate,
				References:  nil,
				//Tags:        tags,
				Solutions: "",
				From:      "https://stack.chaitin.com/vuldb/detail/" + d.Id,
				Creator:   t,
			}
			results = append(results, info)
		}
	}

	// 根据 ID 去重
	uniqResults := make(map[string]*VulnInfo)
	for _, info := range results {
		uniqResults[info.UniqueKey] = info
	}
	// 保持顺序
	newResults := make([]*VulnInfo, 0, len(uniqResults))
	for _, info := range results {
		if uniqResults[info.UniqueKey] == nil {
			continue
		}
		newResults = append(newResults, info)
		uniqResults[info.UniqueKey] = nil
	}
	t.log.Infof("got %d vulns from chaitin api", len(newResults))
	return newResults, nil
}

func (t *ChaitinCrawler) IsValuable(info *VulnInfo) bool {
	if info.Severity != High && info.Severity != Critical {
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
			Id                string      `json:"id"`
			Title             string      `json:"title"`
			TitleEn           interface{} `json:"title_en"`
			Summary           string      `json:"summary"`
			SummaryEn         *string     `json:"summary_en"`
			Weakness          string      `json:"weakness"`
			Severity          string      `json:"severity"`
			Cvss3             interface{} `json:"cvss3"`
			Cvss2             interface{} `json:"cvss2"`
			CtId              string      `json:"ct_id"`
			CveId             string      `json:"cve_id"`
			CnvdId            interface{} `json:"cnvd_id"`
			CnnvdId           *string     `json:"cnnvd_id"`
			FixSteps          interface{} `json:"fix_steps"`
			References        *string     `json:"references"`
			DisclosureDate    *string     `json:"disclosure_date"`
			PocDisclosureDate interface{} `json:"poc_disclosure_date"`
			ExpDisclosureDate interface{} `json:"exp_disclosure_date"`
			PatchDate         interface{} `json:"patch_date"`
			Impact            interface{} `json:"impact"`
			CreatedAt         time.Time   `json:"created_at"`
			UpdatedAt         time.Time   `json:"updated_at"`
			PocId             interface{} `json:"poc_id"`
			BountyTime        interface{} `json:"bounty_time"`
			BountyRewardScore int         `json:"bounty_reward_score"`
		} `json:"list"`
	} `json:"data"`
	Code int `json:"code"`
}
