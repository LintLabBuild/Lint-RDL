// Package config loads and saves rdl's config file. Config can only be
// changed at the PC (CLI or by editing the file), never from chat, the web
// UI or MCP.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/lintlabbuild/lint-rdl/internal/policy"
	"github.com/lintlabbuild/lint-rdl/internal/state"
)

// Config mirrors config.yaml. See docs/CONFIG.md.
type Config struct {
	Roots           []string
	Deny            []string
	DefaultRoot     string
	DiskMinFreeGB   float64
	MaxParallelJobs int
	SegmentsPerFile int
	SpeedLimit      string // "off" or e.g. "5MB/s"
	BrowseShowFiles bool
	BlockExtensions string // off | warn | block
	AllowPrivate    []string
	DomainAllowlist []string
	Proxy           string
	AllowOverwrite  bool // reserved; never used by phase 1

	ChunkMB          int // fsync + journal every N MB
	StallSeconds     int // abort a request after N seconds without bytes
	LowSpeedBytes    int64
	LowSpeedSeconds  int
	MaxMkdirDepth    int
	RetryAfterCapSec int

	Web      WebConfig
	Telegram TelegramConfig
	Power    PowerConfig

	path string
}

// WebConfig is the web UI section (phase 2).
type WebConfig struct {
	Enabled bool
	Bind    string
}

// TelegramConfig is the Telegram section (phase 3). The token lives in the
// OS credential store, never here.
type TelegramConfig struct {
	Enabled bool
}

// PowerConfig is the power section (phase 2).
type PowerConfig struct {
	CountdownSeconds int
	AgentCanPower    bool
}

// Default returns the built-in defaults.
func Default() *Config {
	return &Config{
		DiskMinFreeGB:    10,
		MaxParallelJobs:  3,
		SegmentsPerFile:  1,
		SpeedLimit:       "off",
		BlockExtensions:  "warn",
		ChunkMB:          8,
		StallSeconds:     120,
		LowSpeedBytes:    0,
		LowSpeedSeconds:  60,
		MaxMkdirDepth:    8,
		RetryAfterCapSec: 3600,
		Web:              WebConfig{Enabled: false, Bind: "127.0.0.1:8765"},
		Power:            PowerConfig{CountdownSeconds: 60},
	}
}

// Path returns the file this config was loaded from (or will be saved to).
func (c *Config) Path() string { return c.path }

// ConfigDir is %APPDATA%\rdl on Windows, $XDG_CONFIG_HOME/rdl elsewhere.
// RDL_CONFIG_DIR overrides it.
func ConfigDir() string {
	if d := os.Getenv("RDL_CONFIG_DIR"); d != "" {
		return d
	}
	d, err := os.UserConfigDir()
	if err != nil {
		return ".rdl-config"
	}
	return filepath.Join(d, "rdl")
}

// StateDir is %LOCALAPPDATA%\rdl on Windows, $XDG_STATE_HOME/rdl (or
// ~/.local/state/rdl) elsewhere. RDL_STATE_DIR overrides it.
func StateDir() string {
	if d := os.Getenv("RDL_STATE_DIR"); d != "" {
		return d
	}
	if runtime.GOOS == "windows" {
		if d := os.Getenv("LOCALAPPDATA"); d != "" {
			return filepath.Join(d, "rdl")
		}
	}
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return filepath.Join(d, "rdl")
	}
	if h, err := os.UserHomeDir(); err == nil {
		if runtime.GOOS == "darwin" {
			return filepath.Join(h, "Library", "Application Support", "rdl", "state")
		}
		return filepath.Join(h, ".local", "state", "rdl")
	}
	return ".rdl-state"
}

// DefaultPath is ConfigDir()/config.yaml.
func DefaultPath() string { return filepath.Join(ConfigDir(), "config.yaml") }

// Load reads path. A missing file yields defaults (and remembers path).
func Load(path string) (*Config, error) {
	c := Default()
	c.path = path
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	if err := c.parse(string(data)); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, c.Validate()
}

// Parse parses YAML text into a config bound to path (used by
// `rdl config set`, which edits the rendered text and re-validates it).
func Parse(src, path string) (*Config, error) {
	c := Default()
	c.path = path
	if err := c.parse(src); err != nil {
		return nil, err
	}
	return c, c.Validate()
}

func (c *Config) parse(src string) error {
	vals, err := parseYAML(src)
	if err != nil {
		return err
	}
	for key, v := range vals {
		if err := c.set(key, v); err != nil {
			return fmt.Errorf("line %d: %s: %w", v.line, key, err)
		}
	}
	return nil
}

func wantScalar(v *yamlValue) (string, error) {
	if v.isList || v.isMap {
		return "", errors.New("expected a single value")
	}
	return v.scalar, nil
}

func wantList(v *yamlValue) ([]string, error) {
	if v.isMap || (!v.isList && v.scalar != "") {
		return nil, errors.New("expected a list")
	}
	return append([]string{}, v.list...), nil
}

func wantMap(v *yamlValue) (map[string]string, error) {
	if v.isList || (!v.isMap && v.scalar != "") {
		return nil, errors.New("expected a section")
	}
	if v.m == nil {
		return map[string]string{}, nil
	}
	return v.m, nil
}

func parseBool(s string) (bool, error) {
	switch strings.ToLower(s) {
	case "true", "yes", "on":
		return true, nil
	case "false", "no", "off", "":
		return false, nil
	}
	return false, fmt.Errorf("expected true or false, got %q", s)
}

func (c *Config) set(key string, v *yamlValue) error {
	var err error
	scalarInt := func(dst *int) error {
		s, err := wantScalar(v)
		if err != nil {
			return err
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			return err
		}
		*dst = n
		return nil
	}
	switch key {
	case "roots":
		c.Roots, err = wantList(v)
	case "deny":
		c.Deny, err = wantList(v)
	case "allow_private":
		c.AllowPrivate, err = wantList(v)
	case "domain_allowlist":
		c.DomainAllowlist, err = wantList(v)
	case "default_root":
		c.DefaultRoot, err = wantScalar(v)
	case "speed_limit":
		c.SpeedLimit, err = wantScalar(v)
	case "block_extensions":
		c.BlockExtensions, err = wantScalar(v)
	case "proxy":
		c.Proxy, err = wantScalar(v)
	case "disk_min_free_gb":
		var s string
		if s, err = wantScalar(v); err == nil {
			c.DiskMinFreeGB, err = strconv.ParseFloat(s, 64)
		}
	case "max_parallel_jobs":
		err = scalarInt(&c.MaxParallelJobs)
	case "segments_per_file":
		err = scalarInt(&c.SegmentsPerFile)
	case "chunk_mb":
		err = scalarInt(&c.ChunkMB)
	case "stall_seconds":
		err = scalarInt(&c.StallSeconds)
	case "low_speed_seconds":
		err = scalarInt(&c.LowSpeedSeconds)
	case "max_mkdir_depth":
		err = scalarInt(&c.MaxMkdirDepth)
	case "retry_after_cap_seconds":
		err = scalarInt(&c.RetryAfterCapSec)
	case "low_speed_bytes":
		var s string
		if s, err = wantScalar(v); err == nil {
			c.LowSpeedBytes, err = ParseSize(s)
		}
	case "browse_show_files":
		var s string
		if s, err = wantScalar(v); err == nil {
			c.BrowseShowFiles, err = parseBool(s)
		}
	case "allow_overwrite":
		var s string
		if s, err = wantScalar(v); err == nil {
			c.AllowOverwrite, err = parseBool(s)
		}
	case "web":
		var m map[string]string
		if m, err = wantMap(v); err == nil {
			for k, s := range m {
				switch k {
				case "enabled":
					c.Web.Enabled, err = parseBool(s)
				case "bind":
					c.Web.Bind = s
				default:
					err = fmt.Errorf("unknown key web.%s", k)
				}
				if err != nil {
					return err
				}
			}
		}
	case "telegram":
		var m map[string]string
		if m, err = wantMap(v); err == nil {
			for k, s := range m {
				switch k {
				case "enabled":
					c.Telegram.Enabled, err = parseBool(s)
				default:
					err = fmt.Errorf("unknown key telegram.%s", k)
				}
				if err != nil {
					return err
				}
			}
		}
	case "power":
		var m map[string]string
		if m, err = wantMap(v); err == nil {
			for k, s := range m {
				switch k {
				case "countdown_seconds":
					c.Power.CountdownSeconds, err = strconv.Atoi(s)
				case "agent_can_power":
					c.Power.AgentCanPower, err = parseBool(s)
				default:
					err = fmt.Errorf("unknown key power.%s", k)
				}
				if err != nil {
					return err
				}
			}
		}
	default:
		return fmt.Errorf("unknown key")
	}
	return err
}

// Validate checks values and reports the first problem.
func (c *Config) Validate() error {
	switch c.BlockExtensions {
	case "off", "warn", "block":
	default:
		return fmt.Errorf("block_extensions must be off, warn or block")
	}
	if c.MaxParallelJobs < 1 || c.MaxParallelJobs > 32 {
		return fmt.Errorf("max_parallel_jobs must be 1..32")
	}
	if c.SegmentsPerFile < 1 || c.SegmentsPerFile > 16 {
		return fmt.Errorf("segments_per_file must be 1..16")
	}
	if c.ChunkMB < 1 || c.ChunkMB > 1024 {
		return fmt.Errorf("chunk_mb must be 1..1024")
	}
	if c.DiskMinFreeGB < 0 {
		return fmt.Errorf("disk_min_free_gb must be >= 0")
	}
	if _, err := c.SpeedLimitBytes(); err != nil {
		return err
	}
	for _, a := range c.AllowPrivate {
		if _, err := policy.ParseAllowPrivate(a); err != nil {
			return fmt.Errorf("allow_private %q: %v", a, err)
		}
	}
	if c.Proxy != "" {
		u, err := url.Parse(c.Proxy)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("proxy must be an http(s) URL")
		}
	}
	for _, r := range c.Roots {
		if !filepath.IsAbs(r) {
			return fmt.Errorf("root %q must be an absolute path", r)
		}
	}
	return nil
}

// SpeedLimitBytes returns the global speed cap in bytes/s (0 = off).
func (c *Config) SpeedLimitBytes() (int64, error) {
	s := strings.TrimSpace(strings.ToLower(c.SpeedLimit))
	if s == "" || s == "off" || s == "0" {
		return 0, nil
	}
	s = strings.TrimSuffix(s, "/s")
	n, err := ParseSize(s)
	if err != nil {
		return 0, fmt.Errorf("speed_limit: %w", err)
	}
	return n, nil
}

// ParseSize parses "5MB", "512k", "1.5GB", "1000" into bytes (binary units).
func ParseSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	s = strings.TrimSuffix(s, "IB")
	s = strings.TrimSuffix(s, "B")
	mult := float64(1)
	if s != "" {
		switch s[len(s)-1] {
		case 'K':
			mult = 1 << 10
		case 'M':
			mult = 1 << 20
		case 'G':
			mult = 1 << 30
		case 'T':
			mult = 1 << 40
		}
		if mult != 1 {
			s = s[:len(s)-1]
		}
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || f < 0 {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return int64(f * mult), nil
}

// PathPolicy builds the path policy from this config.
func (c *Config) PathPolicy() *policy.PathPolicy {
	roots := append([]string{}, c.Roots...)
	if c.DefaultRoot != "" {
		// Put the default root first.
		out := []string{c.DefaultRoot}
		for _, r := range roots {
			if !strings.EqualFold(filepath.Clean(r), filepath.Clean(c.DefaultRoot)) {
				out = append(out, r)
			}
		}
		roots = out
	}
	return &policy.PathPolicy{
		Roots:     roots,
		Deny:      c.Deny,
		Forbidden: policy.DefaultForbidden(ConfigDir(), StateDir(), filepath.Dir(c.path)),
		MaxDepth:  c.MaxMkdirDepth,
	}
}

// URLPolicy builds the URL policy from this config.
func (c *Config) URLPolicy() (*policy.URLPolicy, error) {
	p := &policy.URLPolicy{DomainAllowlist: c.DomainAllowlist}
	for _, a := range c.AllowPrivate {
		pr, err := policy.ParseAllowPrivate(a)
		if err != nil {
			return nil, err
		}
		p.AllowPrivate = append(p.AllowPrivate, pr)
	}
	if c.Proxy != "" {
		u, err := url.Parse(c.Proxy)
		if err != nil {
			return nil, err
		}
		p.Proxy = u
	}
	return p, nil
}

// AllowPrivatePrefixes parses AllowPrivate.
func (c *Config) AllowPrivatePrefixes() []netip.Prefix {
	var out []netip.Prefix
	for _, a := range c.AllowPrivate {
		if p, err := policy.ParseAllowPrivate(a); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// StallTimeout returns the stall timeout.
func (c *Config) StallTimeout() time.Duration { return time.Duration(c.StallSeconds) * time.Second }

// Save writes the config atomically to its path.
func (c *Config) Save() error {
	if c.path == "" {
		c.path = DefaultPath()
	}
	if err := c.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	return state.WriteFileAtomic(c.path, []byte(c.Render()), 0o600)
}

// Render returns the config as YAML text.
func (c *Config) Render() string {
	var b strings.Builder
	list := func(key string, items []string, comment string) {
		if comment != "" {
			b.WriteString("# " + comment + "\n")
		}
		if len(items) == 0 {
			b.WriteString(key + ": []\n")
			return
		}
		b.WriteString(key + ":\n")
		for _, it := range items {
			b.WriteString("  - " + quoteYAML(it) + "\n")
		}
	}
	kv := func(key, val string) { b.WriteString(key + ": " + val + "\n") }
	b.WriteString("# rdl config. Edit at the PC only; remote interfaces can't change it.\n")
	list("roots", c.Roots, "Folders downloads may be saved in. The first (or default_root) is the default.")
	list("deny", c.Deny, "Folders that are forbidden even inside a root.")
	kv("default_root", quoteYAML(c.DefaultRoot))
	kv("disk_min_free_gb", strconv.FormatFloat(c.DiskMinFreeGB, 'f', -1, 64))
	kv("max_parallel_jobs", strconv.Itoa(c.MaxParallelJobs))
	kv("segments_per_file", strconv.Itoa(c.SegmentsPerFile))
	kv("speed_limit", quoteYAML(c.SpeedLimit))
	kv("browse_show_files", strconv.FormatBool(c.BrowseShowFiles))
	kv("block_extensions", quoteYAML(c.BlockExtensions))
	list("allow_private", c.AllowPrivate, "Private addresses allowed as download sources. Only editable at the PC.")
	list("domain_allowlist", c.DomainAllowlist, "Empty = any public domain.")
	kv("proxy", quoteYAML(c.Proxy))
	kv("chunk_mb", strconv.Itoa(c.ChunkMB))
	kv("stall_seconds", strconv.Itoa(c.StallSeconds))
	kv("low_speed_bytes", strconv.FormatInt(c.LowSpeedBytes, 10))
	kv("low_speed_seconds", strconv.Itoa(c.LowSpeedSeconds))
	kv("max_mkdir_depth", strconv.Itoa(c.MaxMkdirDepth))
	kv("retry_after_cap_seconds", strconv.Itoa(c.RetryAfterCapSec))
	b.WriteString("web:\n")
	b.WriteString("  enabled: " + strconv.FormatBool(c.Web.Enabled) + "\n")
	b.WriteString("  bind: " + quoteYAML(c.Web.Bind) + "\n")
	b.WriteString("telegram:\n")
	b.WriteString("  enabled: " + strconv.FormatBool(c.Telegram.Enabled) + "  # token lives in the OS credential store\n")
	b.WriteString("power:\n")
	b.WriteString("  countdown_seconds: " + strconv.Itoa(c.Power.CountdownSeconds) + "\n")
	b.WriteString("  agent_can_power: " + strconv.FormatBool(c.Power.AgentCanPower) + "\n")
	return b.String()
}
