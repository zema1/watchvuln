package grab

import (
	"context"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestChaitin(t *testing.T) {
	assert := require.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*300)
	defer cancel()
	grab := NewChaitinCrawler()
	vulns, err := grab.GetUpdate(ctx, 3)
	assert.Nil(err)

	count := 0
	for _, v := range vulns {
		t.Logf("get vuln info %s", v)
		count++
		assert.NotEmpty(v.UniqueKey)
		assert.NotEmpty(v.Title)
		assert.NotEmpty(v.Disclosure)
		assert.NotEmpty(v.From)
	}
	assert.Equal(count, 45)
}

func TestChineseCharacter(t *testing.T) {
	assert := require.New(t)
	assert.False(ContainsChinese("hello"))
	assert.False(ContainsChinese("CVE-2023-0101"))
	assert.True(ContainsChinese("CyberPanel upgrademysqlstatus 远程命令执行漏洞"))
}
