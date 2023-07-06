package ctrl

import (
	"context"
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGithubSearch(t *testing.T) {
	assert := require.New(t)

	app, err := NewApp(&WatchVulnAppConfig{
		DBConn:          "",
		Sources:         nil,
		Interval:        30,
		EnableCVEFilter: false,
		NoGithubSearch:  false,
		NoStartMessage:  false,
		NoFilter:        false,
		Version:         "",
	}, nil, nil)
	assert.Nil(err)
	links, err := app.FindGithubPoc(context.Background(), "CVE-2023-25157")
	assert.Nil(err)
	fmt.Println(links)
}
