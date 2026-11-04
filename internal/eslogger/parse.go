package eslogger

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/echtermeyer/overlord/internal/events"
)

// The subset of eslogger's JSON we keep. Everything else is skipped by encoding/json.
type record struct {
	Time    string                     `json:"time"`
	Process process                    `json:"process"`
	Event   map[string]json.RawMessage `json:"event"`
}

type auditToken struct {
	PID        int `json:"pid"`
	PIDVersion int `json:"pidversion"`
	EUID       int `json:"euid"`
}

type file struct {
	Path string `json:"path"`
}

type process struct {
	AuditToken       auditToken `json:"audit_token"`
	ParentAuditToken auditToken `json:"parent_audit_token"`
	ResponsibleToken auditToken `json:"responsible_audit_token"`
	PPID             int        `json:"ppid"`
	StartTime        string     `json:"start_time"`
	IsPlatformBinary bool       `json:"is_platform_binary"`
	SigningID        string     `json:"signing_id"`
	TeamID           string     `json:"team_id"`
	CDHash           string     `json:"cdhash"`
	TTY              *file      `json:"tty"`
	Executable       file       `json:"executable"`
}

func (p process) toProcess() events.Process {
	start, _ := time.Parse(time.RFC3339Nano, p.StartTime)
	out := events.Process{
		PID:         p.AuditToken.PID,
		PIDVersion:  p.AuditToken.PIDVersion,
		PPID:        p.PPID,
		Responsible: p.ResponsibleToken.PID,
		UID:         p.AuditToken.EUID,
		Path:        p.Executable.Path,
		SigningID:   p.SigningID,
		TeamID:      p.TeamID,
		CDHash:      p.CDHash,
		Platform:    p.IsPlatformBinary,
		Start:       start,
	}
	if p.TTY != nil {
		out.TTY = p.TTY.Path
	}
	return out
}

type execEvent struct {
	Target process  `json:"target"`
	Args   []string `json:"args"`
	CWD    *file    `json:"cwd"`
}

type forkEvent struct {
	Child process `json:"child"`
}

type exitEvent struct {
	Stat int `json:"stat"`
}

type openEvent struct {
	File  file `json:"file"`
	FFlag int  `json:"fflag"`
}

type destination struct {
	ExistingFile *file `json:"existing_file"`
	NewPath      *struct {
		Dir      file   `json:"dir"`
		Filename string `json:"filename"`
	} `json:"new_path"`
}

func (d destination) path() string {
	if d.ExistingFile != nil {
		return d.ExistingFile.Path
	}
	if d.NewPath != nil {
		return strings.TrimRight(d.NewPath.Dir.Path, "/") + "/" + d.NewPath.Filename
	}
	return ""
}

type createEvent struct {
	Destination destination `json:"destination"`
}

type renameEvent struct {
	Source      file        `json:"source"`
	Destination destination `json:"destination"`
}

type targetEvent struct {
	Target file `json:"target"`
}

type writeEvent struct {
	Target file `json:"target"`
}

type btmItem struct {
	ItemType       int    `json:"item_type"`
	Legacy         bool   `json:"legacy"`
	ItemURL        string `json:"item_url"`
	AppURL         string `json:"app_url"`
	ExecutablePath string `json:"executable_path"`
}

type btmEvent struct {
	Instigator *process `json:"instigator"`
	App        *process `json:"app"`
	Item       btmItem  `json:"item"`
}

type sudoEvent struct {
	Success        bool   `json:"success"`
	Command        string `json:"command"`
	FailureMessage string `json:"failure_message"`
	FromUsername   string `json:"from_username"`
}

type tccEvent struct {
	Service    string `json:"service"`
	Identity   string `json:"identity"`
	UpdateType int    `json:"update_type"`
	Right      int    `json:"right"`
}

type malwareEvent struct {
	MalwareIdentifier string `json:"malware_identifier"`
	DetectedPath      string `json:"detected_path"`
	SignatureVersion  string `json:"signature_version"`
}

type sshEvent struct {
	Success       bool   `json:"success"`
	SourceAddress string `json:"source_address"`
	Username      string `json:"username"`
}

type remoteThreadEvent struct {
	Target process `json:"target"`
}

type mountEvent struct {
	Statfs struct {
		FMntonname   string `json:"f_mntonname"`
		FMntfromname string `json:"f_mntfromname"`
		FFstypename  string `json:"f_fstypename"`
	} `json:"statfs"`
}

type kextEvent struct {
	Identifier string `json:"identifier"`
}

var launchItemTypes = map[int]string{0: "user_item", 1: "app", 2: "login_item", 3: "agent", 4: "daemon"}

const (
	oWRONLY = 0x0001
	oRDWR   = 0x0002
	oCREAT  = 0x0200
	oTRUNC  = 0x0400
)

// Parse turns one eslogger line into an event. Lines for event types the graph does not use
// return (nil, nil).
func Parse(line []byte) (*events.Event, error) {
	var r record
	if err := json.Unmarshal(line, &r); err != nil {
		return nil, fmt.Errorf("eslogger line: %w", err)
	}
	if len(r.Event) != 1 {
		return nil, fmt.Errorf("eslogger line: %d event keys", len(r.Event))
	}
	at, _ := time.Parse(time.RFC3339Nano, r.Time)
	ev := &events.Event{At: at, Source: "eslogger", Process: r.Process.toProcess()}
	for name, raw := range r.Event {
		if err := fill(ev, name, raw); err != nil {
			return nil, err
		}
	}
	if ev.Kind == "" {
		return nil, nil
	}
	return ev, nil
}

func fill(ev *events.Event, name string, raw json.RawMessage) error {
	switch name {
	case "exec":
		var e execEvent
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		ev.Kind = events.Exec
		t := e.Target.toProcess()
		t.Args = e.Args
		if e.CWD != nil {
			t.CWD = e.CWD.Path
		}
		ev.Target = &t
	case "fork":
		var e forkEvent
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		ev.Kind = events.Fork
		c := e.Child.toProcess()
		ev.Target = &c
	case "exit":
		var e exitEvent
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		ev.Kind = events.Exit
		ev.ExitStatus = e.Stat
	case "open":
		var e openEvent
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		ev.Kind = events.FileOpen
		ev.Path = e.File.Path
		ev.Write = e.FFlag&(oWRONLY|oRDWR|oCREAT|oTRUNC) != 0
	case "create":
		var e createEvent
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		ev.Kind = events.FileCreate
		ev.Path = e.Destination.path()
		ev.Write = true
	case "write":
		var e writeEvent
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		ev.Kind = events.FileWrite
		ev.Path = e.Target.Path
		ev.Write = true
	case "rename":
		var e renameEvent
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		ev.Kind = events.FileRename
		ev.Path = e.Source.Path
		ev.DestPath = e.Destination.path()
		ev.Write = true
	case "unlink":
		var e targetEvent
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		ev.Kind = events.FileUnlink
		ev.Path = e.Target.Path
		ev.Write = true
	case "btm_launch_item_add", "btm_launch_item_remove":
		var e btmEvent
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		ev.Kind = events.LaunchItemAdd
		if name == "btm_launch_item_remove" {
			ev.Kind = events.LaunchItemRemove
		}
		ev.LaunchItem = &events.LaunchItem{
			Type:       launchItemTypes[e.Item.ItemType],
			ItemURL:    e.Item.ItemURL,
			AppURL:     e.Item.AppURL,
			Executable: e.Item.ExecutablePath,
			Legacy:     e.Item.Legacy,
		}
		ev.Path = strings.TrimPrefix(e.Item.ItemURL, "file://")
		if e.Instigator != nil {
			ev.Process = e.Instigator.toProcess()
		}
	case "sudo":
		var e sudoEvent
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		ev.Kind = events.Sudo
		ev.Detail = map[string]string{
			"success": fmt.Sprint(e.Success), "command": e.Command,
			"failure": e.FailureMessage, "from_user": e.FromUsername,
		}
	case "tcc_modify":
		var e tccEvent
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		ev.Kind = events.TCCModify
		ev.Detail = map[string]string{
			"service": e.Service, "identity": e.Identity,
			"update_type": fmt.Sprint(e.UpdateType), "right": fmt.Sprint(e.Right),
		}
	case "xp_malware_detected":
		var e malwareEvent
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		ev.Kind = events.MalwareDetected
		ev.Path = e.DetectedPath
		ev.Detail = map[string]string{"malware": e.MalwareIdentifier, "signatures": e.SignatureVersion}
	case "openssh_login":
		var e sshEvent
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		ev.Kind = events.SSHLogin
		ev.Detail = map[string]string{"success": fmt.Sprint(e.Success), "source": e.SourceAddress, "user": e.Username}
	case "remote_thread_create":
		var e remoteThreadEvent
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		ev.Kind = events.RemoteThread
		t := e.Target.toProcess()
		ev.Target = &t
	case "mount":
		var e mountEvent
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		ev.Kind = events.Mount
		ev.Path = e.Statfs.FMntonname
		ev.Detail = map[string]string{"from": e.Statfs.FMntfromname, "fstype": e.Statfs.FFstypename}
	case "kextload":
		var e kextEvent
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		ev.Kind = events.KextLoad
		ev.Detail = map[string]string{"identifier": e.Identifier}
	}
	return nil
}
