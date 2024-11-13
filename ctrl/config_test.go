package ctrl

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestWatchVulnAppConfig_DBConnForEnt(t *testing.T) {
	assert := require.New(t)

	// sqlite3 test cases
	c := &WatchVulnAppConfig{
		DBConn: "sqlite3://vuln_v3.db",
	}
	dialect, conn, err := c.DBConnForEnt()
	assert.Nil(err)
	assert.Equal("sqlite3", dialect)
	assert.Equal("file:vuln_v3.db?cache=shared&_pragma=foreign_keys(1)", conn)

	c = &WatchVulnAppConfig{
		DBConn: "sqlite3:///tmp/vuln_v3.db",
	}
	dialect, conn, err = c.DBConnForEnt()
	assert.Nil(err)
	assert.Equal("sqlite3", dialect)
	assert.Equal("file:/tmp/vuln_v3.db?cache=shared&_pragma=foreign_keys(1)", conn)

	c = &WatchVulnAppConfig{
		DBConn: "sqlite3://D:/vuln_v3.db",
	}
	dialect, conn, err = c.DBConnForEnt()
	assert.Nil(err)
	assert.Equal("sqlite3", dialect)
	assert.Equal("file:D:/vuln_v3.db?cache=shared&_pragma=foreign_keys(1)", conn)

	c = &WatchVulnAppConfig{
		DBConn: "sqlite3://vuln_v3.sqlite3?cache=shared",
	}
	dialect, conn, err = c.DBConnForEnt()
	assert.Nil(err)
	assert.Equal("sqlite3", dialect)
	assert.Equal("file:vuln_v3.sqlite3?cache=shared", conn)

	// mysql test cases
	c = &WatchVulnAppConfig{
		DBConn: "mysql://user:pass@host:123/dbname",
	}
	dialect, conn, err = c.DBConnForEnt()
	assert.Nil(err)
	assert.Equal("mysql", dialect)
	assert.Equal("user:pass@tcp(host:123)/dbname?charset=utf8mb4&parseTime=True&loc=Local", conn)

	c = &WatchVulnAppConfig{
		DBConn: "mysql://user:pass@host:123/dbname?charset=gbk&parseTime=True&loc=Local",
	}
	dialect, conn, err = c.DBConnForEnt()
	assert.Nil(err)
	assert.Equal("mysql", dialect)
	assert.Equal("user:pass@tcp(host:123)/dbname?charset=gbk&parseTime=True&loc=Local", conn)

	c = &WatchVulnAppConfig{
		DBConn: "mysql://user:pass@host:123",
	}
	dialect, conn, err = c.DBConnForEnt()
	assert.Nil(err)
	assert.Equal("mysql", dialect)
	assert.Equal("user:pass@tcp(host:123)/?charset=utf8mb4&parseTime=True&loc=Local", conn)

	c = &WatchVulnAppConfig{
		DBConn: "mysql://user:pass@host",
	}
	dialect, conn, err = c.DBConnForEnt()
	assert.Nil(err)
	assert.Equal("mysql", dialect)
	assert.Equal("user:pass@tcp(host)/?charset=utf8mb4&parseTime=True&loc=Local", conn)

	// postgres test cases
	c = &WatchVulnAppConfig{
		DBConn: "postgres://user:pass@host:123/dbname",
	}
	dialect, conn, err = c.DBConnForEnt()
	assert.Nil(err)
	assert.Equal("postgres", dialect)
	assert.Equal("postgresql://user:pass@host:123/dbname?sslmode=disable", conn)

	c = &WatchVulnAppConfig{
		DBConn: "postgres://user:pass@host:123/dbname?sslmode=enable",
	}
	dialect, conn, err = c.DBConnForEnt()
	assert.Nil(err)
	assert.Equal("postgres", dialect)
	assert.Equal("postgresql://user:pass@host:123/dbname?sslmode=enable", conn)

	c = &WatchVulnAppConfig{
		DBConn: "postgres://user:pass@host:123",
	}
	dialect, conn, err = c.DBConnForEnt()
	assert.Nil(err)
	assert.Equal("postgres", dialect)
	assert.Equal("postgresql://user:pass@host:123/?sslmode=disable", conn)

	c = &WatchVulnAppConfig{
		DBConn: "postgres://user:pass@host",
	}
	dialect, conn, err = c.DBConnForEnt()
	assert.Nil(err)
	assert.Equal("postgres", dialect)
	assert.Equal("postgresql://user:pass@host/?sslmode=disable", conn)

	// error case
	c = &WatchVulnAppConfig{
		DBConn: "unknown://user:pass@host",
	}
	dialect, conn, err = c.DBConnForEnt()
	assert.NotNil(err)
	assert.Equal("", dialect)
	assert.Equal("", conn)
}
