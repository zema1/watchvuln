package ctrl

import (
	"context"
	"fmt"
	"github.com/stretchr/testify/require"
	"regexp"
	"testing"
)

func TestGithubSearch(t *testing.T) {
	t.Skipf("local tests")
	assert := require.New(t)

	app, err := NewApp(&WatchVulnAppConfig{
		DBConn:   "sqlite3://vuln_v3.sqlite3",
		Sources:  nil,
		Interval: "30h",
		Version:  "",
	})
	assert.Nil(err)
	links, err := app.FindGithubPoc(context.Background(), "CVE-2023-37582")
	assert.Nil(err)
	fmt.Println(links)
}

func TestReMatch(t *testing.T) {
	re := regexp.MustCompile("(?i)[\b/_]CVE-2023-37582[\b/_]")
	fmt.Println(re.MatchString("https://github.com/Malayke/CVE-2023-37582_EXPLOIT"))
}
