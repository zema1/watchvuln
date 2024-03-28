package push

import (
	"fmt"
	"testing"

	"github.com/kataras/golog"
	"github.com/stretchr/testify/assert"
)

var lanxin = newLanxin()

func newLanxin() *LanXin {
	return &LanXin{
		// 下面要填入能用的domain、token和secret
		domain: "",
		token:  "",
		secret: "",
		log:    golog.Child("[pusher-lanxin]"),
	}
}

func TestLanxinSendText(t *testing.T) {
	t.Skip("local test lanxin")
	result, err := lanxin.Send("6666")
	fmt.Println(result)
	assert.Nil(t, err)
	assert.Contains(t, result.ErrMsg, "OK")
}
