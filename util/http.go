package util

import (
	"context"
	"errors"
	"github.com/imroc/req/v3"
	"github.com/kataras/golog"
	"time"
)

func NewHttpClient() *req.Client {
	client := req.C()
	client.
		ImpersonateChrome().
		SetTimeout(10 * time.Second).
		SetCommonRetryCount(3).
		SetCookieJar(nil).
		SetCommonRetryInterval(func(resp *req.Response, attempt int) time.Duration {
			if errors.Is(resp.Err, context.Canceled) {
				return 0
			}
			return time.Second * 5
		}).
		SetCommonRetryHook(func(resp *req.Response, err error) {
			if err != nil {
				if !errors.Is(err, context.Canceled) {
					golog.Warnf("retrying as %s", err)
				}
			}
		}).SetCommonRetryCondition(func(resp *req.Response, err error) bool {
		if err != nil {
			return !errors.Is(err, context.Canceled)
		}
		return false
	})
	return client
}

func WrapApiClient(client *req.Client) *req.Client {
	return client.SetCommonHeaders(map[string]string{
		"Accept":             "application/json, text/plain, */*",
		"Accept-Language":    "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
		"Content-Type":       "application/json",
		"Sec-Fetch-Dest":     "empty",
		"Sec-Fetch-Mode":     "cors",
		"Sec-Fetch-Site":     "same-origin",
		"sec-ch-ua":          `"Microsoft Edge";v="111", "Not(A:Brand";v="8", "Chromium";v="111"`,
		"sec-ch-ua-mobile":   `?0`,
		"sec-ch-ua-platform": `"Windows"`,
	})
}
