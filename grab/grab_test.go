package grab

import (
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestMergeUniqueString(t *testing.T) {
	assert := require.New(t)

	results := MergeUniqueString([]string{"a", "b"}, []string{"b", "c"})
	assert.Equal(3, len(results))
	results = MergeUniqueString(nil, strings.Split("https://fourcore.io/blogs/cve-2023-36884-ms-office-zero-day-vulnerability\nhttps://www.microsoft.com/en-us/security/blog/2023/07/11/storm-0978-attacks-reveal-financial-and-espionage-motives/\nhttps://blog.cyble.com/2023/07/12/microsoft-zero-day-vulnerability-cve-2023-36884-being-actively-exploited/", "\n"))
	assert.Equal(3, len(results))
}
