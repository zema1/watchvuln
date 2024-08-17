package grab

import (
	"context"
	"github.com/zema1/watchvuln/util"
	"time"

	"github.com/imroc/req/v3"
	"github.com/kataras/golog"
	"github.com/pkg/errors"
)

type ThreatBookCrawler struct {
	client *req.Client
	log    *golog.Logger
}

func NewThreatBookCrawler() Grabber {
	client := util.NewHttpClient()
	client.SetCommonHeader("Referer", "https://x.threatbook.com/v5/vulIntelligence")
	client.SetCommonHeader("Origin", "https://mp.weixin.qq.com/")
	client.SetCommonHeader("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6")

	return &ThreatBookCrawler{
		log:    golog.Child("[threatbook]"),
		client: client,
	}
}

func (t *ThreatBookCrawler) ProviderInfo() *Provider {
	return &Provider{
		Name:        "threatbook",
		DisplayName: "微步在线研究响应中心-漏洞通告",
		Link:        "https://x.threatbook.com/v5/vulIntelligence",
	}
}

func (t *ThreatBookCrawler) GetUpdate(ctx context.Context, pageLimit int) ([]*VulnInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second) // 增加超时
	defer cancel()
	var results []*VulnInfo

	resp, err := t.client.R().Get("https://x.threatbook.com/v5/node/vul_module/homePage")
	if err != nil {
		return nil, err
	}
	var body threatBookHomepage
	err = resp.UnmarshalJson(&body)
	if err != nil {
		return nil, err
	}
	t.log.Infof("got %d vulns", len(body.Data.HighRisk))

	for _, v := range body.Data.HighRisk {
		disclosure := v.VulnPublishTime
		if disclosure == "" {
			disclosure = v.VulnUpdateTime
		}
		var tags []string
		if v.Is0Day {
			tags = append(tags, "0day")
		}
		if v.PocExist {
			tags = append(tags, "有Poc")
		}
		if v.Premium {
			tags = append(tags, "有漏洞分析")
		}
		if v.Solution {
			tags = append(tags, "有修复方案")
		}
		vuln := &VulnInfo{
			UniqueKey:  v.Id,
			Title:      v.VulnNameZh,
			Severity:   Critical,
			Disclosure: disclosure,
			Solutions:  "",
			References: nil,
			Tags:       tags,
			From:       t.ProviderInfo().Link,
			Creator:    t,
		}
		results = append(results, vuln)
	}
	t.log.Infof("got %d vulns", len(results))

	return results, nil
}

func (t *ThreatBookCrawler) IsValuable(info *VulnInfo) bool {
	// 漏洞太多了，规则严格一些
	var hasPoc, hasAnalysis bool
	for _, tag := range info.Tags {
		if tag == "有Poc" {
			hasPoc = true
		}
		if tag == "有漏洞分析" {
			hasAnalysis = true
		}
	}
	if !hasPoc || !hasAnalysis {
		return false
	}
	if info.Disclosure == "" {
		return false
	}
	// 2024-04-29 format
	dis, err := time.Parse("2006-01-02", info.Disclosure)
	if err != nil {
		t.log.Error(errors.Wrap(err, "parse disclosure time"))
		return false
	}
	// 只看两周内的，古董漏洞就别推了
	if time.Since(dis) > 14*24*time.Hour {
		return false
	}

	return true
}

type threatBookHomepage struct {
	Data struct {
		HighRisk []struct {
			Id              string   `json:"id"`
			VulnNameZh      string   `json:"vuln_name_zh"`
			VulnUpdateTime  string   `json:"vuln_update_time"`
			Affects         []string `json:"affects"`
			VulnPublishTime string   `json:"vuln_publish_time,omitempty"`
			PocExist        bool     `json:"pocExist"`
			Solution        bool     `json:"solution"`
			Premium         bool     `json:"premium"`
			RiskLevel       string   `json:"riskLevel"`
			Is0Day          bool     `json:"is0day,omitempty"`
		} `json:"highrisk"`
	} `json:"data"`
	ResponseCode int `json:"response_code"`
}
