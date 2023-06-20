package ctrl

import "time"

type WatchVulnAppConfig struct {
	DBConn          string        `yaml:"db_conn" json:"db_conn"`
	Sources         []string      `yaml:"sources" json:"sources"`
	Interval        time.Duration `yaml:"interval" json:"interval"`
	EnableCVEFilter bool          `yaml:"enable_cve_filter" json:"enable_cve_filter"`
	NoNucleiSearch  bool          `yaml:"no_nuclei_search" json:"no_nuclei_search"`
	NoStartMessage  bool          `yaml:"no_start_message" json:"no_start_message"`
	NoFilter        bool          `yaml:"no_filter" json:"no_filter"`
	Version         string        `yaml:"version" json:"version"`
}
