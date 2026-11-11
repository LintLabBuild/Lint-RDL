//go:build windows

package favorites

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// psScript lists folders pinned to Quick access (Windows 10) / Home
// (Windows 11). It is a fixed string: no user input ever reaches it.
const psScript = `$ErrorActionPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$qa=(New-Object -ComObject Shell.Application).Namespace('shell:::{679f85cb-0220-4080-b29b-5540cc05aab6}')
foreach($i in $qa.Items()){
  if(-not $i.IsFolder){continue}
  $pinned=$i.ExtendedProperty('System.Home.IsPinned')
  if($pinned -ne $true){ $pinned = [bool]($i.Verbs() | Where-Object { $_.Name -match 'unpin' }) }
  if($pinned -and $i.Path -match '^[A-Za-z]:\\'){ Write-Output ($i.Path + "` + "`t" + `" + $i.Name) }
}`

func list() []Folder {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	ps := filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", psScript)
	out, err := cmd.Output()
	if err != nil && len(out) == 0 {
		return nil
	}
	var res []Folder
	for _, line := range strings.Split(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n") {
		p, label, _ := strings.Cut(strings.TrimSpace(line), "\t")
		if p != "" {
			res = append(res, Folder{Path: p, Label: label, Source: "explorer"})
		}
	}
	return res
}
