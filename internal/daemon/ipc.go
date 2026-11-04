package daemon

import (
	"context"
	"encoding/json"
	"os"
	"syscall"
	"time"

	"github.com/echtermeyer/overlord/internal/hooks"
	"github.com/echtermeyer/overlord/internal/ipc"
	"github.com/echtermeyer/overlord/internal/notify"
)

func (d *Daemon) serveIPC(ctx context.Context) error {
	srv := ipc.NewServer(d.cfg.Socket, 0o666, d.handleIPC)
	return srv.ListenAndServe(ctx)
}

func ok(v any) ipc.Response {
	raw, err := json.Marshal(v)
	if err != nil {
		return fail(err.Error())
	}
	return ipc.Response{OK: true, Payload: raw}
}

func fail(msg string) ipc.Response { return ipc.Response{OK: false, Error: msg} }

// consoleUID is the uid that owns the console, the person at the keyboard.
func consoleUID() int {
	info, err := os.Stat("/dev/console")
	if err != nil {
		return -1
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(stat.Uid)
	}
	return -1
}

func (d *Daemon) handleIPC(ctx context.Context, c *ipc.Conn, req ipc.Request) ipc.Response {
	switch req.Type {
	case "status":
		return ok(d.Status())
	case "tool_call":
		var call hooks.Call
		if err := json.Unmarshal(req.Payload, &call); err != nil {
			return fail(err.Error())
		}
		if call.Info.AgentPID == 0 {
			call.Info.AgentPID = c.Peer.PID
		}
		ctx, cancel := context.WithTimeout(ctx, d.cfg.Hook.DaemonTimeout)
		defer cancel()
		return ok(d.ToolCall(ctx, call))
	case "subscribe":
		if c.Peer.UID == 0 || (consoleUID() >= 0 && c.Peer.UID != consoleUID()) {
			return fail("only the console user may answer asks")
		}
		go d.pushAsks(ctx, c)
		return ipc.Response{}
	case "reply":
		var ans notify.Answer
		if err := json.Unmarshal(req.Payload, &ans); err != nil {
			return fail(err.Error())
		}
		if c.Peer.UID == 0 || (consoleUID() >= 0 && c.Peer.UID != consoleUID()) {
			return fail("only the console user may answer asks")
		}
		ans.UID = c.Peer.UID
		if !d.broker.Answer(ans) {
			return fail("no such ask")
		}
		return ipc.Response{}
	case "allow":
		if c.Peer.UID != 0 && c.Peer.UID != consoleUID() {
			return fail("root or the console user may add allow entries")
		}
		var e AllowEntry
		if err := json.Unmarshal(req.Payload, &e); err != nil {
			return fail(err.Error())
		}
		if e.Rule == "" || e.Kind == "" || e.Value == "" {
			return fail("rule, kind and value are required")
		}
		e.UID = c.Peer.UID
		if err := d.allow.Add(e); err != nil {
			return fail(err.Error())
		}
		d.log("action", map[string]any{"action": "allow_always", "entry": e, "by": c.Peer.UID})
		return ok(e)
	case "allowlist":
		return ok(d.allow.Entries())
	case "manifests":
		return ok(d.actions.List())
	case "undo", "resume", "kill":
		if c.Peer.UID != 0 {
			return fail("root only")
		}
		var arg struct {
			ID  string `json:"id"`
			PID int    `json:"pid"`
		}
		if err := json.Unmarshal(req.Payload, &arg); err != nil {
			return fail(err.Error())
		}
		var err error
		switch req.Type {
		case "undo":
			err = d.actions.Undo(arg.ID)
		case "resume":
			err = d.actions.Resume(arg.PID)
		case "kill":
			err = d.actions.Kill(arg.PID)
		}
		d.actResult(req.Type, arg.ID+itoa(arg.PID), "manual", nil, err)
		if err != nil {
			return fail(err.Error())
		}
		return ok("done")
	case "santa_block":
		if c.Peer.UID != 0 || d.santa == nil {
			return fail("root only, and Santa must be enabled")
		}
		var arg struct {
			Type, Identifier, Message string
		}
		if err := json.Unmarshal(req.Payload, &arg); err != nil {
			return fail(err.Error())
		}
		if err := d.santa.Block(arg.Type, arg.Identifier, arg.Message); err != nil {
			return fail(err.Error())
		}
		return ok("done")
	}
	return fail("unknown request " + req.Type)
}

func itoa(i int) string {
	if i == 0 {
		return ""
	}
	raw, _ := json.Marshal(i)
	return string(raw)
}

func (d *Daemon) pushAsks(ctx context.Context, c *ipc.Conn) {
	_, asks, cancel := d.broker.Subscribe()
	defer cancel()
	d.log("notify_subscribed", map[string]int{"uid": c.Peer.UID, "pid": c.Peer.PID})
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.Done():
			return
		case a := <-asks:
			raw, _ := json.Marshal(a)
			if err := c.Send(ipc.Response{ID: a.ID, OK: true, Payload: raw}); err != nil {
				return
			}
		case <-ticker.C:
			if err := c.Send(ipc.Response{OK: true, Payload: json.RawMessage(`{"ping":true}`)}); err != nil {
				return
			}
		}
	}
}
