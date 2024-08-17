package grab

import (
	"context"
	"github.com/zema1/watchvuln/util"
	"strconv"
	"strings"

	"github.com/imroc/req/v3"
	"github.com/kataras/golog"
)

type TiCrawler struct {
	client *req.Client
	log    *golog.Logger
}

func NewTiCrawler() Grabber {
	client := util.WrapApiClient(util.NewHttpClient())
	client.SetCommonHeader("Referer", "https: //ti.qianxin.com/")
	client.SetCommonHeader("Origin", "https: //ti.qianxin.com")

	c := &TiCrawler{
		log:    golog.Child("[qianxin-nox]"),
		client: client,
	}
	return c
}

func (t *TiCrawler) ProviderInfo() *Provider {
	return &Provider{
		Name:        "qianxin-ti",
		DisplayName: "奇安信威胁情报中心",
		Link:        "https://ti.qianxin.com/",
	}
}

func (t *TiCrawler) GetUpdate(ctx context.Context, _ int) ([]*VulnInfo, error) {
	resp, err := t.client.R().
		SetContext(ctx).
		Post("https://ti.qianxin.com/alpha-api/v2/vuln/one-day")
	if err != nil {
		return nil, err
	}
	var body tiOneDayResp
	if err = resp.UnmarshalJson(&body); err != nil {
		return nil, err
	}
	var results []*VulnInfo
	for _, d := range body.Data.KeyVulnAdd {
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
			From:        "https://ti.qianxin.com/vulnerability/detail/" + strconv.Itoa(d.Id),
			Creator:     t,
		}
		results = append(results, info)
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
	t.log.Infof("got %d vulns from oneday api", len(newResults))
	return newResults, nil
}

func (t *TiCrawler) IsValuable(info *VulnInfo) bool {
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

type tiVulnDetail struct {
	Id                int     `json:"id"`
	VulnName          string  `json:"vuln_name"`
	VulnNameEn        string  `json:"vuln_name_en"`
	QvdCode           string  `json:"qvd_code"`
	CveCode           string  `json:"cve_code"`
	CnvdId            *string `json:"cnvd_id"`
	CnnvdId           string  `json:"cnnvd_id"`
	ThreatCategory    string  `json:"threat_category"`
	TechnicalCategory string  `json:"technical_category"`
	ResidenceId       *int    `json:"residence_id"`
	RatingId          *int    `json:"rating_id"`
	NotShow           int     `json:"not_show"`
	PublishTime       string  `json:"publish_time"`
	Description       string  `json:"description"`
	DescriptionEn     string  `json:"description_en"`
	ChangeImpact      int     `json:"change_impact"`
	OperatorHid       string  `json:"operator_hid"`
	CreateHid         *string `json:"create_hid"`
	Channel           *string `json:"channel"`
	TrackingId        *string `json:"tracking_id"`
	Temp              int     `json:"temp"`
	OtherRating       int     `json:"other_rating"`
	CreateTime        string  `json:"create_time"`
	UpdateTime        string  `json:"update_time"`
	LatestUpdateTime  string  `json:"latest_update_time"`
	RatingLevel       string  `json:"rating_level"`
	VulnType          string  `json:"vuln_type"`
	PocFlag           int     `json:"poc_flag"`
	PatchFlag         int     `json:"patch_flag"`
	DetailFlag        int     `json:"detail_flag"`
	Tag               []struct {
		Name      string `json:"name"`
		FontColor string `json:"font_color"`
		BackColor string `json:"back_color"`
	} `json:"tag"`
	TagLen        int `json:"tag_len"`
	IsRatingLevel int `json:"is_rating_level"`
}

type tiOneDayResp struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
	Data    struct {
		VulnAddCount    int            `json:"vuln_add_count"`
		VulnUpdateCount int            `json:"vuln_update_count"`
		KeyVulnAddCount int            `json:"key_vuln_add_count"`
		PocExpAddCount  int            `json:"poc_exp_add_count"`
		PatchAddCount   int            `json:"patch_add_count"`
		KeyVulnAdd      []tiVulnDetail `json:"key_vuln_add"`
		PocExpAdd       []tiVulnDetail `json:"poc_exp_add"`
	} `json:"data"`
}
