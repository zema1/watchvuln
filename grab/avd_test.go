package grab

import (
	"context"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestAVD(t *testing.T) {
	assert := require.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*300)
	defer cancel()
	grab := NewAVDCrawler()
	count, err := grab.GetPageCount(ctx, 100)
	assert.Nil(err)
	assert.True(count > 0)

	vulns, err := grab.ParsePage(ctx, 1, 100)
	assert.Nil(err)

	count = 0
	for v := range vulns {
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
