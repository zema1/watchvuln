package ctrl

import (
	"fmt"
	"net/url"
	"time"

	"entgo.io/ent/dialect"
)

type WatchVulnAppConfig struct {
	DBConn          string        `yaml:"db_conn" json:"db_conn"`
	Sources         []string      `yaml:"sources" json:"sources"`
	Interval        time.Duration `yaml:"interval" json:"interval"`
	EnableCVEFilter bool          `yaml:"enable_cve_filter" json:"enable_cve_filter"`
	NoGithubSearch  bool          `yaml:"no_github_search" json:"no_github_search"`
	NoStartMessage  bool          `yaml:"no_start_message" json:"no_start_message"`
	NoFilter        bool          `yaml:"no_filter" json:"no_filter"`
	DiffMode        bool          `yaml:"diff_mode" json:"diff_mode`
	Version         string        `yaml:"version" json:"version"`
}

const dbExample = `
sqlite3://vuln_v3.sqlite3
mysql://user:pass@host:port/dbname
postgres://user:pass@host:port/dbname
`

func (c *WatchVulnAppConfig) DBConnForEnt() (string, string, error) {
	u, err := url.Parse(c.DBConn)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse db_conn: %w, expected:%s", err, dbExample)
	}
	switch u.Scheme {
	case dialect.SQLite:
		query := `cache=shared&_pragma=foreign_keys(1)`
		if u.RawQuery != "" {
			query = u.RawQuery
		}
		return dialect.SQLite, fmt.Sprintf("file:%s?%s", u.Host, query), nil
	case dialect.MySQL:
		path := ""
		if u.Path != "" {
			path = u.Path[1:]
		}
		query := `charset=utf8mb4&parseTime=True&loc=Local`
		if u.RawQuery != "" {
			query = u.RawQuery
		}
		return dialect.MySQL, fmt.Sprintf("%s@tcp(%s)/%s?%s", u.User.String(), u.Host, path, query), nil
	case dialect.Postgres:
		path := ""
		if u.Path != "" {
			path = u.Path[1:]
		}
		query := `sslmode=disable`
		if u.RawQuery != "" {
			query = u.RawQuery
		}
		return dialect.Postgres, fmt.Sprintf("postgresql://%s@%s/%s?%s", u.User.String(), u.Host, path, query), nil
	default:
		return "", "", fmt.Errorf("unsupported db_conn: %s, expected:%s", c.DBConn, dbExample)
	}
}
