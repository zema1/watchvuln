package grab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/imroc/req/v3"
	"github.com/kataras/golog"
	"strings"
)

type NoxCrawler struct {
	client *req.Client
	log    *golog.Logger
}

func NewNoxCrawler() Grabber {
	client := wrapApiClient(NewHttpClient())
	client.SetCommonHeader("Referer", "https://nox.qianxin.com/KeyPoint")
	client.SetCommonHeader("Origin", "https://nox.qianxin.com")
	c := &NoxCrawler{
		log:    golog.Child("[qianxin-nox]"),
		client: client,
	}
	return c
}

func (t *NoxCrawler) ProviderInfo() *Provider {
	return &Provider{
		Name:        "qianxin-nox",
		DisplayName: "奇安信安全监测平台",
		Link:        "https://nox.qianxin.com/KeyPoint",
	}
}

func (t *NoxCrawler) GetPageCount(ctx context.Context, size int) (int, error) {
	var body noxListResp

	_, err := t.client.R().
		SetBodyBytes(t.buildBody(1, 10)).
		SetContext(ctx).
		AddRetryCondition(func(resp *req.Response, err error) bool {
			if err != nil {
				return !errors.Is(err, context.Canceled)
			}
			if err = resp.UnmarshalJson(&body); err != nil {
				t.log.Warnf("unmarshal json error, %s", err)
				return true
			}
			if body.RespCode != 0 {
				t.log.Warnf("failed to get page count, msg: %s, retrying", body.RespMessage)
				return true
			}
			if body.Data.Total <= 0 {
				t.log.Warnf("invalid total size %d, retrying", body.Data.Total)
				return true
			}
			return false
		}).
		Post("https://nox.qianxin.com/api/web/portal/key_vuln/list")
	if err != nil {
		return 0, err
	}

	total := body.Data.Total

	if total <= 0 || size <= 0 {
		return 0, fmt.Errorf("invalid size %d %d", total, size)
	}

	pageCount := total / size
	if pageCount == 0 {
		return 1, nil
	}
	if total%pageCount != 0 {
		pageCount += 1
	}
	return pageCount, nil
}

func (t *NoxCrawler) ParsePage(ctx context.Context, page, size int) (chan *VulnInfo, error) {
	t.log.Infof("parsing page %d", page)
	resp, err := t.client.R().
		SetContext(ctx).
		SetBodyBytes(t.buildBody(page, size)).
		Post("https://nox.qianxin.com/api/web/portal/key_vuln/list")
	if err != nil {
		return nil, err
	}
	var body noxListResp
	if err = resp.UnmarshalJson(&body); err != nil {
		return nil, err
	}
	t.log.Infof("got %d vulns from page %d", len(body.Data.Data), page)
	result := make(chan *VulnInfo, 1)
	go func() {
		defer close(result)
		for _, d := range body.Data.Data {
			select {
			case <-ctx.Done():
				return
			default:
			}

			tags := make([]string, 0, len(d.Tag))
			for _, tag := range d.Tag {
				tags = append(tags, strings.TrimSpace(tag.Name))
			}
			severity := Low
			switch d.RatingLevel {
			case "低危":
				severity = Low
			case "中危":
				severity = Medium
			case "高危":
				severity = High
			case "极危":
				severity = Critical
			}
			info := &VulnInfo{
				UniqueKey:   d.QvdCode,
				Title:       d.VulnName,
				Description: d.Description,
				Severity:    severity,
				CVE:         d.CveCode,
				Disclosure:  d.PublishTime,
				References:  nil,
				Tags:        tags,
				Solutions:   "",
				From:        "https://nox.qianxin.com/vulnerability/detail/" + d.QvdCode,
				Creator:     t,
			}
			// 有限制先去掉了: 您今日的漏洞详情查看次数已达上限，请明天再试
			//err = t.updateDetail(strconv.Itoa(d.Id), info)
			//if err != nil {
			//	t.log.Warnf("failed to update %s detail, %s", d.QvdCode, err)
			//}
			result <- info
		}
	}()
	return result, nil
}

func (t *NoxCrawler) IsValuable(info *VulnInfo) bool {
	if info.Severity != High && info.Severity != Critical {
		return false
	}
	for _, tag := range info.Tags {
		if tag == "奇安信CERT验证" ||
			tag == "POC公开" ||
			tag == "EXP公开" ||
			tag == "技术细节公布" {
			return true
		}
	}
	return false
}

func (t *NoxCrawler) buildBody(page, size int) []byte {
	m := map[string]interface{}{
		"page_no":      page,
		"page_size":    size,
		"vuln_keyword": "",
	}
	data, _ := json.Marshal(m)
	return data
}

func (t *NoxCrawler) updateDetail(id string, v *VulnInfo) error {
	t.log.Debugf("parsing details of %s", v.From)
	resp, err := t.client.R().
		SetBodyBytes([]byte(fmt.Sprintf(`{"id":"%s"}`, id))).
		Post("https://nox.qianxin.com/api/web/portal/vuln/residence/temp/show")
	if err != nil {
		return err
	}
	var body noxDetailResp
	if err = resp.UnmarshalJson(&body); err != nil {
		return err
	}
	if body.RespCode != 0 {
		return fmt.Errorf("failed to get detail, msg: %s", body.RespMessage)
	}
	for _, info := range body.Data.ResidenceLatest {
		info.Value = strings.TrimSpace(info.Value)
		switch info.Key {
		case "fix_method":
			v.Solutions = info.Value
		case "related_links":
			if info.Value == "" {
				continue
			}
			v.References = MergeUniqueString(v.References, strings.Split(info.Value, "\n"))
		}
	}
	return nil
}

type noxListResp struct {
	Sid         string `json:"sid"`
	RespCode    int    `json:"resp_code"`
	RespMessage string `json:"resp_message"`
	Data        struct {
		Data []struct {
			Id                int     `json:"id"`
			VulnName          string  `json:"vuln_name"`
			VulnNameEn        string  `json:"vuln_name_en"`
			QvdCode           string  `json:"qvd_code"`
			CveCode           string  `json:"cve_code"`
			CnvdId            *string `json:"cnvd_id"`
			CnnvdId           *string `json:"cnnvd_id"`
			ThreatCategory    string  `json:"threat_category"`
			TechnicalCategory string  `json:"technical_category"`
			ResidenceId       int     `json:"residence_id"`
			RatingId          int     `json:"rating_id"`
			NotShow           int     `json:"not_show"`
			PublishTime       string  `json:"publish_time"`
			Description       string  `json:"description"`
			DescriptionEn     string  `json:"description_en"`
			ChangeImpact      int     `json:"change_impact"`
			OperatorHid       string  `json:"operator_hid"`
			CreateHid         string  `json:"create_hid"`
			Temp              int     `json:"temp"`
			OtherRating       int     `json:"other_rating"`
			CreateTime        string  `json:"create_time"`
			UpdateTime        string  `json:"update_time"`
			LatestUpdateTime  string  `json:"latest_update_time"`
			RatingLevel       string  `json:"rating_level"`
			VulnType          string  `json:"vuln_type"`
			PocFlag           int     `json:"poc_flag"`
			Tag               []struct {
				Name      string `json:"name"`
				FontColor string `json:"font_color"`
				BackColor string `json:"back_color"`
			} `json:"tag"`
			UsedFlag           int    `json:"used_flag"`
			PublicFlag         int    `json:"public_flag"`
			MaliciousType      string `json:"malicious_type"`
			QpeProdName        string `json:"qpe_prod_name"`
			QpeManufactureName string `json:"qpe_manufacture_name"`
		} `json:"data"`
		Total int `json:"total"`
	} `json:"data"`
}

type noxDetailResp struct {
	Sid         string `json:"sid"`
	RespCode    int    `json:"resp_code"`
	RespMessage string `json:"resp_message"`
	Data        struct {
		ResidenceLatest []struct {
			Label string `json:"label"`
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"residence_latest"`
		ResidenceTemp []interface{} `json:"residence_temp"`
		Id            int           `json:"id"`
		VulnName      string        `json:"vuln_name"`
		CveCode       string        `json:"cve_code"`
	} `json:"data"`
}
