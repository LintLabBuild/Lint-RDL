package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/lintlabbuild/lint-rdl/internal/adapters/mcp"
	"github.com/lintlabbuild/lint-rdl/internal/command"
)

// cmdMCP runs the MCP server on stdin/stdout. Until the background
// service exists (#7) it runs the download engine itself: downloads run
// while the agent keeps it open, and unfinished ones resume with `rdl run`.
func cmdMCP(args []string, stdout, stderr io.Writer) error {
	fs := newFlags("mcp")
	printCfg := fs.Bool("print-config", false, "")
	if _, err := parseInterspersed(fs, args); err != nil {
		return fmt.Errorf("usage: rdl mcp [--print-config]")
	}
	if *printCfg {
		exe, err := os.Executable()
		if err != nil {
			exe = "rdl"
		}
		cfg := map[string]any{"mcpServers": map[string]any{"rdl": map[string]any{"command": exe, "args": []string{"mcp"}}}}
		b, _ := json.MarshalIndent(cfg, "", "  ")
		fmt.Fprintf(stdout, "%s\n\nClaude Code: claude mcp add rdl -- %q mcp\n", b, exe)
		return nil
	}
	a, err := openApp(true)
	if err != nil {
		return err
	}
	defer a.close()
	if len(a.paths.Roots) == 0 {
		return errNoRoots
	}
	// Agents see what remote users would see.
	a.disp.ShowFiles = a.cfg.BrowseShowFiles
	a.disp.Limits = command.Limits{CommandsPerMinute: 300, AgentCanPower: a.cfg.Power.AgentCanPower}
	a.m.Start()

	ctx, cancel := signalContext()
	defer cancel()
	go func() {
		t := time.NewTicker(3 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				a.m.Rescan()
			}
		}
	}()
	s := &mcp.Server{D: a.disp, Name: "rdl", Version: version, Log: stderr}
	fmt.Fprintln(stderr, "rdl mcp: ready (stdio). Unfinished downloads resume later with `rdl run`.")
	return s.Serve(ctx, os.Stdin, stdout)
}
