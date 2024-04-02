package grab

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestKEV(t *testing.T) {
	assert := require.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*300)
	defer cancel()
	grab := NewKEVCrawler()
	vulns, err := grab.GetUpdate(ctx, 5)
	assert.Nil(err)

	count := 0
	for _, v := range vulns {
		t.Logf("get vuln info %s", v)
		count++
		assert.NotEmpty(v.UniqueKey)
		assert.NotEmpty(v.Description)
		assert.NotEmpty(v.Title)
		assert.NotEmpty(v.Disclosure)
		assert.NotEmpty(v.Severity)
		assert.NotEmpty(v.References)

	}
	assert.Equal(count, 50)
}
