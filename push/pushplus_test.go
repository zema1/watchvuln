package push

import (
	"testing"

	"github.com/kataras/golog"
	"github.com/stretchr/testify/assert"
)

var pushplus = newPushPlus()

func newPushPlus() *PushPlus {
	return &PushPlus{
		token: "", // 这里输入可用的key
		log:   golog.Child("[pusher-push-plus]"),
	}
}

func TestPushPlusSendTxt(t *testing.T) {
	t.Skip("local test plusplus")
	message := PushPlusMessage{
		Title:    "test1",
		Content:  `<h1>纯文本内容</h1>`,
		Template: "txt",
	}

	result, err1 := pushplus.Send(message)
	assert.Nil(t, err1)
	assert.Contains(t, result.Msg, "请求成功")
}

func TestPushPlusSendMarkdown(t *testing.T) {
	t.Skip("local test plusplus")
	message := PushPlusMessage{
		Title:    "test",
		Content:  "# 内容",
		Template: "markdown",
	}

	result, err := pushplus.Send(message)
	assert.Nil(t, err)
	assert.Contains(t, result.Msg, "请求成功")
}
