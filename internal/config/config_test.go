package config

import (
	"path/filepath"
	"strings"
	"testing"
)

const specExample = `roots:
  - D:\Downloads
  - D:\files\A_Project_folder
deny:
  - D:\files\A_Project_folder\secrets
default_root: D:\Downloads
disk_min_free_gb: 10
max_parallel_jobs: 3
segments_per_file: 1          # >1 = parallel ranges
speed_limit: off
browse_show_files: false
block_extensions: warn        # off | warn | block
allow_private: []             # only editable at the PC
domain_allowlist: []          # empty = any public domain
web:
  enabled: true
  bind: 127.0.0.1:8765
telegram:
  enabled: true               # token lives in Credential Manager
power:
  countdown_seconds: 60
  agent_can_power: false
`

func TestParseSpecExample(t *testing.T) {
	c := Default()
	if err := c.parse(specExample); err != nil {
		t.Fatal(err)
	}
	if len(c.Roots) != 2 || c.Roots[1] != `D:\files\A_Project_folder` || c.DefaultRoot != `D:\Downloads` {
		t.Fatalf("%+v", c)
	}
	if !c.Web.Enabled || c.Web.Bind != "127.0.0.1:8765" || !c.Telegram.Enabled || c.Power.CountdownSeconds != 60 {
		t.Fatalf("%+v", c)
	}
}

func TestRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	c := Default()
	c.path = path
	c.Roots = []string{filepath.Join(t.TempDir(), "it's a folder #1")}
	c.AllowPrivate = []string{"192.168.1.50"}
	c.SpeedLimit = "5MB/s"
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	c2, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c2.Roots[0] != c.Roots[0] || c2.AllowPrivate[0] != "192.168.1.50" || c2.SpeedLimit != "5MB/s" {
		t.Fatalf("%+v", c2)
	}
	if n, _ := c2.SpeedLimitBytes(); n != 5<<20 {
		t.Fatal(n)
	}
}

func TestRejects(t *testing.T) {
	bad := []string{
		"unknown_key: 1",
		"roots: notalist",
		"max_parallel_jobs: lots",
		"web:\n  surprise: 1",
		"roots:\n  - a\n  b: c",
		"  indented: 1",
		"block_extensions: maybe",
		"allow_private: [not-an-ip]",
		"roots: [relative/path]",
		"speed_limit: fast",
		"proxy: ftp://x",
		"a: 1\na: 2",
	}
	for _, s := range bad {
		if _, err := Parse(s, "x"); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
}

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"5MB": 5 << 20, "512k": 512 << 10, "1.5GB": 3 << 29, "1000": 1000, "2GiB": 2 << 30} {
		if got, err := ParseSize(in); err != nil || got != want {
			t.Errorf("%s = %d %v", in, got, err)
		}
	}
	if !strings.Contains(Default().Render(), "roots: []") {
		t.Fatal("render")
	}
}
