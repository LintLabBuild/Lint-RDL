package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/lintlabbuild/lint-rdl/internal/engine"
	"github.com/lintlabbuild/lint-rdl/internal/inspect"
	"github.com/lintlabbuild/lint-rdl/internal/policy"
)

// isInteractive reports whether both stdin and stdout are terminals.
func isInteractive() bool {
	for _, f := range []*os.File{os.Stdin, os.Stdout} {
		st, err := f.Stat()
		if err != nil || st.Mode()&os.ModeCharDevice == 0 {
			return false
		}
	}
	return true
}

var stdinReader = bufio.NewReader(os.Stdin)

func ask(w io.Writer, prompt string) string {
	fmt.Fprint(w, prompt)
	line, _ := stdinReader.ReadString('\n')
	return strings.TrimSpace(line)
}

// printProbe shows what a link is before anything is downloaded.
func printProbe(w io.Writer, r *engine.ProbeResult, maxEntries int) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "URL\t%s\n", r.URL)
	if r.Kind == "git" && r.Git != nil {
		g := r.Git
		fmt.Fprintf(tw, "Type\tGit repository %s/%s on %s\n", g.Repo.Owner, g.Repo.Name, g.Repo.Host)
		if g.Repo.Ref != "" {
			fmt.Fprintf(tw, "Branch/tag\t%s\n", g.Repo.Ref)
		}
		if g.Info != nil {
			if g.Info.Description != "" {
				fmt.Fprintf(tw, "About\t%s\n", g.Info.Description)
			}
			if g.Info.License != "" {
				fmt.Fprintf(tw, "License\t%s\n", g.Info.License)
			}
			if g.Info.Archived {
				fmt.Fprintf(tw, "Note\tthis repository is archived (read-only)\n")
			}
		}
		installed := "yes"
		if !g.GitInstalled {
			installed = "NO"
		}
		fmt.Fprintf(tw, "Git installed\t%s\n", installed)
	} else {
		if r.FinalURL != "" && r.FinalURL != r.URL {
			fu := r.FinalURL
			if len(fu) > 100 {
				fu = fu[:100] + "..."
			}
			extra := fmt.Sprintf("%d redirects", r.Redirects)
			if r.Signed {
				extra += ", signed"
				if r.ExpiresIn > 0 {
					extra += ", expires in ~" + r.ExpiresIn.Round(time.Minute).String()
				}
			}
			fmt.Fprintf(tw, "Final URL\t%s (%s)\n", fu, extra)
		}
		if r.Type != nil {
			fmt.Fprintf(tw, "Type\t%s\n", r.Type.Description)
		}
		if r.Kind != "folder" {
			fmt.Fprintf(tw, "Size\t%s\n", policy.HumanBytes(r.Size))
			fmt.Fprintf(tw, "Resumable\t%s\n", r.Resumable)
			ver := []string{}
			if r.ETag != "" {
				ver = append(ver, "ETag "+r.ETag)
			}
			if r.LastModified != "" {
				ver = append(ver, "Last-Modified "+r.LastModified)
			}
			if len(ver) == 0 {
				ver = []string{"none"}
			}
			fmt.Fprintf(tw, "Version\t%s\n", strings.Join(ver, "  "))
			if r.SHA256 != "" {
				fmt.Fprintf(tw, "Checksum\tSHA-256 %s\n", r.SHA256)
			} else {
				fmt.Fprintf(tw, "Checksum\tunknown (pass --sha256 to verify)\n")
			}
			fmt.Fprintf(tw, "Filename\t%s (from %s)\n", r.Filename, r.FilenameSource)
			if r.Encoding != "" {
				fmt.Fprintf(tw, "Encoding\t%s\n", r.Encoding)
			}
		}
	}
	if r.Contents != nil {
		fmt.Fprintf(tw, "Contents\t%s\n", r.Contents.Summary)
	}
	for _, n := range r.Notes {
		fmt.Fprintf(tw, "Note\t%s\n", n)
	}
	for _, x := range r.Warnings {
		fmt.Fprintf(tw, "Warning\t%s\n", x)
	}
	fmt.Fprintf(tw, "Verdict\t%s\n", r.Verdict)
	tw.Flush()
	if r.Contents != nil && maxEntries > 0 {
		printEntries(w, r.Contents, maxEntries)
	}
}

func printEntries(w io.Writer, c *inspect.Contents, max int) {
	n := 0
	for _, e := range c.Entries {
		if n >= max {
			break
		}
		size := ""
		if e.Size >= 0 && !e.Dir {
			size = "  " + policy.HumanBytes(e.Size)
		}
		name := e.Name
		if e.Dir && !strings.HasSuffix(name, "/") {
			name += "/"
		}
		fmt.Fprintf(w, "    %s%s\n", name, size)
		n++
	}
	total := c.Files + c.Folders
	if c.Kind == "safetensors" {
		total = len(c.Entries)
	}
	if more := total - n; more > 0 || c.Truncated {
		fmt.Fprintf(w, "    ... and %d more (rdl probe --json shows up to %d)\n", max0(more), inspect.MaxEntries)
	}
}

func max0(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

// pickFolder offers the save folders (configured roots and pinned
// favorites) and returns the chosen path, or "" for the default.
func pickFolder(a *app, w io.Writer) (string, error) {
	sf := a.paths.SaveFolders()
	if len(sf) <= 1 {
		return "", nil
	}
	fmt.Fprintln(w, "\nSave to:")
	for i, f := range sf {
		tag := ""
		switch {
		case i == 0:
			tag = "  (default)"
		case f.Source != "root":
			tag = "  (pinned in " + map[string]string{"explorer": "File Explorer", "gtk": "file manager", "kde": "Dolphin"}[f.Source] + ")"
		}
		fmt.Fprintf(w, "  %d) %-20s %s%s\n", i+1, f.Label, f.Path, tag)
	}
	for {
		ans := ask(w, "Choose a number, or type a subfolder path [1]: ")
		if ans == "" {
			return sf[0].Path, nil
		}
		if n, err := strconv.Atoi(ans); err == nil {
			if n >= 1 && n <= len(sf) {
				return sf[n-1].Path, nil
			}
			fmt.Fprintln(w, "No such number.")
			continue
		}
		if d, err := a.paths.ResolveDir(ans); err == nil {
			return d, nil
		} else {
			fmt.Fprintln(w, "Can't use that folder:", err)
		}
	}
}

func confirm(w io.Writer, prompt string) bool {
	ans := strings.ToLower(ask(w, prompt+" [Y/n]: "))
	return ans == "" || ans == "y" || ans == "yes"
}

type planned struct {
	url    string
	sha    string
	size   int64
	probed *engine.ProbeResult
}

// planDownloads probes every link first and expands web folders when
// --all is given. It prints what each link is unless quiet.
func planDownloads(ctx context.Context, a *app, urls []string, all, quiet bool, w io.Writer) ([]planned, error) {
	var out []planned
	for _, u := range urls {
		r, err := a.m.Probe(ctx, u)
		if err != nil {
			if errors.Is(err, policy.ErrBlocked) {
				return nil, fmt.Errorf("%s: %w", u, err)
			}
			if !quiet {
				fmt.Fprintf(w, "%s: could not inspect (%v); trying anyway\n", u, err)
			}
			out = append(out, planned{url: u})
			continue
		}
		if !quiet {
			printProbe(w, r, 15)
			fmt.Fprintln(w)
		}
		if r.Kind == "folder" {
			if !all {
				return nil, fmt.Errorf("%s is a web folder; add --all to download its %d files (subfolders are not included)", u, r.Contents.Files)
			}
			for _, e := range r.Contents.Entries {
				if !e.Dir {
					out = append(out, planned{url: e.URL})
				}
			}
			continue
		}
		p := planned{url: u, probed: r}
		if r.SHA256 != "" {
			p.sha = r.SHA256
		}
		if r.Kind == "file" && r.Size > 0 && r.Encoding == "" {
			p.size = r.Size
		}
		out = append(out, p)
	}
	return out, nil
}
