package grab

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestThreatBook(t *testing.T) {
	assert := require.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*300)
	defer cancel()
	grab := NewThreatBookCrawler()
	vulns, err := grab.GetUpdate(ctx, 2)
	assert.Nil(err)

	count := 0
	for _, v := range vulns {
		t.Logf("get vuln info %+v", v)
		count++
		assert.NotEmpty(v.UniqueKey)
		assert.NotEmpty(v.Tags)
		assert.NotEmpty(v.Title)
		assert.NotEmpty(v.From)
	}
	assert.Greater(count, 1)
}
