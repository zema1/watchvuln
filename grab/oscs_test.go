package grab

import (
	"context"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestOSCS(t *testing.T) {
	assert := require.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*300)
	defer cancel()
	grab := NewOSCSCrawler()
	vulns, err := grab.GetUpdate(ctx, 3)
	assert.Nil(err)

	count := 0
	for _, v := range vulns {
		t.Logf("get vuln info %s", v)
		count++
		assert.NotEmpty(v.UniqueKey)
		assert.NotEmpty(v.Description)
		assert.NotEmpty(v.Title)
		assert.NotEmpty(v.Disclosure)
		assert.NotEmpty(v.From)
	}
	assert.Equal(count, 30)
}
