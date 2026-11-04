package events

import "time"

type Kind string

const (
	Exec             Kind = "exec"
	Fork             Kind = "fork"
	Exit             Kind = "exit"
	FileOpen         Kind = "file_open"
	FileCreate       Kind = "file_create"
	FileWrite        Kind = "file_write"
	FileRename       Kind = "file_rename"
	FileUnlink       Kind = "file_unlink"
	LaunchItemAdd    Kind = "launch_item_add"
	LaunchItemRemove Kind = "launch_item_remove"
	Sudo             Kind = "sudo"
	TCCModify        Kind = "tcc_modify"
	MalwareDetected  Kind = "xp_malware_detected"
	SSHLogin         Kind = "ssh_login"
	RemoteThread     Kind = "remote_thread_create"
	Mount            Kind = "mount"
	KextLoad         Kind = "kextload"
	ToolCall         Kind = "tool_call"
	ToolResult       Kind = "tool_result"
	NetConnect       Kind = "net_connect"
	SantaExec        Kind = "santa_exec"
	SensorHealth     Kind = "sensor_health"
)

// Process is the identity of a process as the sensors report it. PID and PIDVersion together
// are unique for the lifetime of the host; a reused pid gets a new version.
type Process struct {
	PID         int       `json:"pid"`
	PIDVersion  int       `json:"pidversion"`
	PPID        int       `json:"ppid"`
	Responsible int       `json:"responsible_pid,omitempty"`
	UID         int       `json:"uid"`
	Path        string    `json:"path"`
	SigningID   string    `json:"signing_id,omitempty"`
	TeamID      string    `json:"team_id,omitempty"`
	CDHash      string    `json:"cdhash,omitempty"`
	Platform    bool      `json:"platform"`
	Args        []string  `json:"args,omitempty"`
	CWD         string    `json:"cwd,omitempty"`
	TTY         string    `json:"tty,omitempty"`
	Start       time.Time `json:"start"`
}

func (p Process) Key() string { return Key(p.PID, p.PIDVersion) }

// Event is the normalized form every sensor produces. Fields that do not apply stay zero.
type Event struct {
	Kind    Kind      `json:"kind"`
	At      time.Time `json:"at"`
	Source  string    `json:"source"`
	Process Process   `json:"process"`
	// Target is the process an event is about when it differs from the actor: the new image on
	// exec, the child on fork, the victim of remote_thread_create.
	Target *Process `json:"target,omitempty"`
	Path   string   `json:"path,omitempty"`
	// DestPath is the destination of a rename and the new path of a create.
	DestPath string `json:"dest_path,omitempty"`
	// Write is true for opens with write intent.
	Write bool `json:"write,omitempty"`
	// Launch item, sudo, TCC, malware and ssh details.
	LaunchItem *LaunchItem       `json:"launch_item,omitempty"`
	Detail     map[string]string `json:"detail,omitempty"`
	// Agent tool calls.
	Call *ToolCallInfo `json:"call,omitempty"`
	// Network.
	Dest *Destination `json:"dest,omitempty"`
	// Exit status.
	ExitStatus int `json:"exit_status,omitempty"`
}

type LaunchItem struct {
	Type       string `json:"type"`
	ItemURL    string `json:"item_url"`
	AppURL     string `json:"app_url,omitempty"`
	Executable string `json:"executable,omitempty"`
	Legacy     bool   `json:"legacy,omitempty"`
}

type ToolCallInfo struct {
	Agent      string            `json:"agent"`
	Session    string            `json:"session"`
	Tool       string            `json:"tool"`
	Command    string            `json:"command,omitempty"`
	Paths      []string          `json:"paths,omitempty"`
	CWD        string            `json:"cwd"`
	Project    string            `json:"project,omitempty"`
	AgentPID   int               `json:"agent_pid"`
	Input      map[string]any    `json:"input,omitempty"`
	Transcript string            `json:"transcript,omitempty"`
	Extra      map[string]string `json:"extra,omitempty"`
}

type Destination struct {
	Address    string `json:"address"`
	Port       int    `json:"port"`
	Protocol   string `json:"protocol"`
	SeenBefore bool   `json:"seen_before"`
}

func Key(pid, version int) string {
	return itoa(pid) + ":" + itoa(version)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		n--
		b[n] = '-'
	}
	return string(b[n:])
}
