package push

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseWPushResponseSuccess(t *testing.T) {
	res := &WPushResponse{}
	err := parseWPushResponse([]byte(`{"code":0,"message":"success","data":"16935207684800512"}`), res)
	assert.Nil(t, err)
	assert.NotNil(t, res.Code)
	assert.Equal(t, 0, *res.Code)
}

func TestParseWPushResponseNonZeroCode(t *testing.T) {
	res := &WPushResponse{}
	err := parseWPushResponse([]byte(`{"code":401,"message":"apikey错误"}`), res)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "apikey错误")
}

func TestParseWPushResponseMissingCode(t *testing.T) {
	res := &WPushResponse{}
	err := parseWPushResponse([]byte(`{"message":"ok"}`), res)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "code missing")
}

func TestParseWPushResponseNullCode(t *testing.T) {
	res := &WPushResponse{}
	err := parseWPushResponse([]byte(`{"code":null,"message":"ok"}`), res)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "code missing")
}

func TestParseWPushResponseInvalidJSON(t *testing.T) {
	res := &WPushResponse{}
	err := parseWPushResponse([]byte(`not-json`), res)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "json")
}
