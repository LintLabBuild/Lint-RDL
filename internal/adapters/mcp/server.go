// Package mcp is the MCP (Model Context Protocol) adapter: it lets AI
// agents use rdl as tools over stdio (JSON-RPC 2.0, one message per line).
//
// Like every adapter it only turns tool calls into command.Commands and
// shows the Results. Identity is "mcp:<client name>" with the agent role,
// so the shared command layer enforces own-jobs-only, no power actions,
// rate limits and the audit log.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/lintlabbuild/lint-rdl/internal/command"
)

// ProtocolVersions this server speaks, newest first.
var ProtocolVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

// Server serves MCP over a reader/writer pair.
type Server struct {
	D       *command.Dispatcher
	Name    string // server name shown to clients
	Version string
	// MaxWait caps the wait tool's timeout (default 6h).
	MaxWait time.Duration
	// Log receives diagnostics (never stdout, which carries the protocol).
	Log io.Writer

	mu       sync.Mutex
	identity command.Identity
	inflight map[string]context.CancelFunc
	outMu    sync.Mutex
	out      io.Writer
	wg       sync.WaitGroup
}

type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// JSON-RPC error codes.
const (
	codeParse          = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
)

func (s *Server) logf(format string, a ...any) {
	if s.Log != nil {
		fmt.Fprintf(s.Log, "rdl mcp: "+format+"\n", a...)
	}
}

func (s *Server) send(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		s.logf("marshal: %v", err)
		return
	}
	s.outMu.Lock()
	defer s.outMu.Unlock()
	s.out.Write(append(b, '\n'))
}

func (s *Server) reply(id json.RawMessage, result any) {
	s.send(rpcResponse{JSONRPC: "2.0", ID: id, Result: result})
}

func (s *Server) replyErr(id json.RawMessage, code int, msg string) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	s.send(rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}})
}

var clientNameRe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func (s *Server) ident() command.Identity {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.identity.ID == "" {
		s.identity = command.Identity{ID: "mcp:agent", Via: "mcp", Role: command.RoleAgent}
	}
	return s.identity
}

// Serve reads requests until in is closed or ctx ends, then waits for
// running tool calls to finish (they are cancelled first).
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	if s.MaxWait <= 0 {
		s.MaxWait = 6 * time.Hour
	}
	s.out = out
	s.inflight = map[string]context.CancelFunc{}
	ctx, cancelAll := context.WithCancel(ctx)
	defer func() {
		cancelAll()
		s.wg.Wait()
	}()

	r := bufio.NewReaderSize(in, 64<<10)
	for {
		line, err := r.ReadBytes('\n')
		if len(strings.TrimSpace(string(line))) > 0 {
			s.handle(ctx, line)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}

func (s *Server) handle(ctx context.Context, line []byte) {
	trimmed := strings.TrimSpace(string(line))
	if strings.HasPrefix(trimmed, "[") {
		s.replyErr(nil, codeInvalidRequest, "JSON-RPC batches are not supported")
		return
	}
	var msg rpcMessage
	if err := json.Unmarshal(line, &msg); err != nil {
		s.replyErr(nil, codeParse, "parse error: "+err.Error())
		return
	}
	isNotification := len(msg.ID) == 0 || string(msg.ID) == "null"
	if msg.Method == "" {
		return // a response to something we never send; ignore
	}
	if isNotification {
		switch msg.Method {
		case "notifications/cancelled":
			var p struct {
				RequestID json.RawMessage `json:"requestId"`
			}
			if json.Unmarshal(msg.Params, &p) == nil {
				s.mu.Lock()
				if cancel, ok := s.inflight[string(p.RequestID)]; ok {
					cancel()
				}
				s.mu.Unlock()
			}
		}
		return
	}

	switch msg.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
			ClientInfo      struct {
				Name string `json:"name"`
			} `json:"clientInfo"`
		}
		json.Unmarshal(msg.Params, &p)
		version := ProtocolVersions[0]
		for _, v := range ProtocolVersions {
			if v == p.ProtocolVersion {
				version = v
			}
		}
		name := clientNameRe.ReplaceAllString(p.ClientInfo.Name, "-")
		if name == "" {
			name = "agent"
		}
		if len(name) > 40 {
			name = name[:40]
		}
		s.mu.Lock()
		s.identity = command.Identity{ID: "mcp:" + strings.ToLower(name), Via: "mcp", Role: command.RoleAgent}
		s.mu.Unlock()
		s.reply(msg.ID, map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": s.Name, "version": s.Version},
			"instructions":    instructions,
		})
	case "ping":
		s.reply(msg.ID, map[string]any{})
	case "tools/list":
		s.reply(msg.ID, map[string]any{"tools": toolList()})
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(msg.Params, &p); err != nil || p.Name == "" {
			s.replyErr(msg.ID, codeInvalidParams, "tools/call needs a tool name")
			return
		}
		t, ok := toolByName(p.Name)
		if !ok {
			s.replyErr(msg.ID, codeInvalidParams, "unknown tool: "+p.Name)
			return
		}
		cctx, cancel := context.WithCancel(ctx)
		key := string(msg.ID)
		s.mu.Lock()
		s.inflight[key] = cancel
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				cancel()
				s.mu.Lock()
				delete(s.inflight, key)
				s.mu.Unlock()
			}()
			args := p.Arguments
			if len(args) == 0 || string(args) == "null" {
				args = json.RawMessage("{}")
			}
			data, err := t.run(cctx, s, args)
			if cctx.Err() != nil && ctx.Err() == nil {
				// Cancelled by the client: the spec says not to respond.
				return
			}
			s.reply(msg.ID, toolResult(data, err))
		}()
	default:
		s.replyErr(msg.ID, codeMethodNotFound, "method not found: "+msg.Method)
	}
}

// toolResult wraps a tool's output as MCP content. Results are compact
// JSON text so agents spend few tokens on them.
func toolResult(data any, err error) map[string]any {
	if err != nil {
		return map[string]any{
			"content": []map[string]any{{"type": "text", "text": err.Error()}},
			"isError": true,
		}
	}
	var text string
	switch v := data.(type) {
	case string:
		text = v
	default:
		b, merr := json.Marshal(v)
		if merr != nil {
			text = fmt.Sprint(v)
		} else {
			text = string(b)
		}
	}
	return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}}
}

const instructions = `rdl downloads files from public http(s) links onto this PC, resumes after drops and verifies SHA-256.
Typical flow: probe (optional) -> add or add_batch (or hf_add for Hugging Face) -> wait -> list.
wait blocks until jobs finish or its timeout, so never poll list in a loop.
rdl never reads, opens or uploads file contents, only downloads from public addresses (no private network), and refuses streaming services (YouTube, Netflix, Spotify...) and stream playlists.
Folders: "to" is a save folder path, a path relative to the default folder, or "@Label/sub" (see folders). Folders must exist; rdl never creates them on its own.`
