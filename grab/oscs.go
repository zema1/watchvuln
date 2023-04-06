package grab

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/imroc/req/v3"
	"github.com/kataras/golog"
	"time"
)

type OSCSCrawler struct {
	client *req.Client
	log    *golog.Logger
}

func NewOSCSCrawler() Grabber {
	client := wrapApiClient(NewHttpClient())
	client.SetCommonHeader("Referer", "https://www.oscs1024.com/cm")
	client.SetCommonHeader("Origin", "https://www.oscs1024.com")
	c := &OSCSCrawler{
		client: client,
		log:    golog.Child("[oscs]"),
	}
	return c
}

func (t *OSCSCrawler) ProviderInfo() *Provider {
	return &Provider{
		Name:        "oscs",
		DisplayName: "OSCS开源安全情报预警",
		Link:        "https://www.oscs1024.com/cm",
	}
}

func (t *OSCSCrawler) GetPageCount(ctx context.Context, size int) (int, error) {
	resp, err := t.client.R().
		SetBodyBytes(t.buildListBody(1, 10)).
		SetContext(ctx).
		Post("https://www.oscs1024.com/oscs/v1/intelligence/list")
	if err != nil {
		return 0, err
	}
	var body oscsListResp
	if err = resp.UnmarshalJson(&body); err != nil {
		return 0, err
	}
	if body.Code != 200 || !body.Success {
		return 0, fmt.Errorf("failed to get page count, msg: %s", body.Info)
	}
	total := body.Data.Total
	pageCount := total / size
	if total%pageCount != 0 {
		pageCount += 1
	}
	return pageCount, nil
}

func (t *OSCSCrawler) ParsePage(ctx context.Context, page, size int) (chan *VulnInfo, error) {
	t.log.Infof("parsing page %d", page)
	resp, err := t.client.R().
		SetContext(ctx).
		SetBodyBytes(t.buildListBody(page, size)).
		Post("https://www.oscs1024.com/oscs/v1/intelligence/list")
	if err != nil {
		return nil, err
	}
	var body oscsListResp
	if err = resp.UnmarshalJson(&body); err != nil {
		return nil, err
	}
	t.log.Infof("page %d contains %d vulns", page, len(body.Data.Data))
	result := make(chan *VulnInfo, 1)
	go func() {
		defer close(result)
		for _, d := range body.Data.Data {
			select {
			case <-ctx.Done():
				return
			default:
			}

			var tags []string
			if d.IsPush == 1 {
				tags = append(tags, "发布预警")
			}
			eventType := "公开漏洞"
			switch d.IntelligenceType {
			case 1:
				eventType = "公开漏洞"
			case 2:
				eventType = "墨菲安全独家"
			case 3:
				eventType = "投毒情报"
			}
			tags = append(tags, eventType)
			info, err := t.parseSingeVuln(ctx, d.Mps)
			if err != nil {
				t.log.Errorf("failed to parse %s, %s", d.Url, err)
				continue
			}
			info.Tags = tags
			result <- info
		}
	}()
	return result, nil
}

func (t *OSCSCrawler) IsValuable(info *VulnInfo) bool {
	// 仅有预警的 或高危严重的
	if info.Severity != Critical && info.Severity != High {
		return false
	}
	for _, tag := range info.Tags {
		if tag == "发布预警" {
			return true
		}
	}
	return false
}

func (t *OSCSCrawler) parseSingeVuln(ctx context.Context, mps string) (*VulnInfo, error) {
	resp, err := t.client.R().
		SetContext(ctx).
		SetBodyString(fmt.Sprintf(`{"vuln_no":"%s"}`, mps)).
		Post("https://www.oscs1024.com/oscs/v1/vdb/info")
	if err != nil {
		return nil, err
	}
	var respBody oscsDetailResp
	if err = resp.UnmarshalJson(&respBody); err != nil {
		return nil, err
	}
	if respBody.Code != 200 || !respBody.Success || len(respBody.Data) == 0 {
		return nil, fmt.Errorf("response error %s", respBody.Info)
	}
	data := respBody.Data[0]
	severity := Low
	switch data.Level {
	case "Critical":
		severity = Critical
	case "High":
		severity = High
	case "Medium":
		severity = Medium
	case "Low":
		severity = Low
	}
	disclosure := time.UnixMilli(int64(data.PublishTime)).Format("2006-01-02")
	refs := make([]string, 0, len(data.References))
	for _, ref := range data.References {
		refs = append(refs, ref.Url)
	}

	// oscs 的修复方式是根据版本自动生成的没什么价值
	info := &VulnInfo{
		UniqueKey:   data.VulnNo,
		Title:       data.VulnTitle,
		Description: data.Description,
		Severity:    severity,
		CVE:         data.CveId,
		Disclosure:  disclosure,
		References:  refs,
		Tags:        nil,
		Solutions:   "",
		From:        t.ProviderInfo().Link,
		Creator:     t,
	}
	return info, nil
}

func (t *OSCSCrawler) buildListBody(page, size int) []byte {
	m := map[string]interface{}{
		"page":     page,
		"per_page": size,
	}
	data, _ := json.Marshal(m)
	return data
}

type oscsListResp struct {
	Data struct {
		Total int `json:"total"`
		Data  []*struct {
			Project          []interface{} `json:"project"`
			Id               string        `json:"id"`
			Title            string        `json:"title"`
			Url              string        `json:"url"`
			Mps              string        `json:"mps"`
			IntelligenceType int           `json:"intelligence_type"`
			PublicTime       time.Time     `json:"public_time"`
			IsPush           int           `json:"is_push"`
			IsPoc            int           `json:"is_poc"`
			IsExp            int           `json:"is_exp"`
			Level            string        `json:"level"`
			CreatedAt        time.Time     `json:"created_at"`
			UpdatedAt        time.Time     `json:"updated_at"`
			IsSubscribe      int           `json:"is_subscribe"`
		} `json:"data"`
	} `json:"data"`
	Success bool   `json:"success"`
	Code    int    `json:"code"`
	Time    int    `json:"time"`
	Info    string `json:"info"`
}
type oscsDetailResp struct {
	Data []*struct {
		AttackVector           string        `json:"attack_vector"`
		CvssVector             string        `json:"cvss_vector"`
		Exp                    bool          `json:"exp"`
		ExploitRequirementCost string        `json:"exploit_requirement_cost"`
		Exploitability         string        `json:"exploitability"`
		ScopeInfluence         string        `json:"scope_influence"`
		Source                 string        `json:"source"`
		VulnType               string        `json:"vuln_type"`
		CvssScore              float64       `json:"cvss_score"`
		CveId                  string        `json:"cve_id"`
		VulnCveId              string        `json:"vuln_cve_id"`
		CnvdId                 string        `json:"cnvd_id"`
		IsOrigin               bool          `json:"is_origin"`
		Languages              []interface{} `json:"languages"`
		Description            string        `json:"description"`
		Effect                 []struct {
			AffectedAllVersion bool          `json:"affected_all_version"`
			AffectedVersion    string        `json:"affected_version"`
			EffectId           int           `json:"effect_id"`
			JavaQnList         []interface{} `json:"java_qn_list"`
			MinFixedVersion    string        `json:"min_fixed_version"`
			Name               string        `json:"name"`
			Solutions          []struct {
				Compatibility int    `json:"compatibility"`
				Description   string `json:"description"`
				Type          string `json:"type"`
			} `json:"solutions"`
		} `json:"effect"`
		Influence   int    `json:"influence"`
		Level       string `json:"level"`
		Patch       string `json:"patch"`
		Poc         bool   `json:"poc"`
		PublishTime int64  `json:"publish_time"`
		References  []struct {
			Name string `json:"name"`
			Url  string `json:"url"`
		} `json:"references"`
		SuggestLevel    string        `json:"suggest_level"`
		VulnSuggest     string        `json:"vuln_suggest"`
		Title           string        `json:"title"`
		Troubleshooting []string      `json:"troubleshooting"`
		VulnTitle       string        `json:"vuln_title"`
		VulnCodeUsage   []interface{} `json:"vuln_code_usage"`
		VulnNo          string        `json:"vuln_no"`
		SoulutionData   []string      `json:"soulution_data"`
	} `json:"data"`
	Success bool   `json:"success"`
	Code    int    `json:"code"`
	Time    int    `json:"time"`
	Info    string `json:"info"`
}
