// Package ipc is the daemon's only inbound channel: a unix socket speaking one JSON object per
// line, with the peer's uid known for every connection.
package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type Request struct {
	Type    string          `json:"type"`
	ID      string          `json:"id,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type Response struct {
	ID      string          `json:"id,omitempty"`
	OK      bool            `json:"ok"`
	Error   string          `json:"error,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Peer is who is on the other end, from the kernel, not from the message.
type Peer struct {
	UID int
	GID int
	PID int
}

type Conn struct {
	Peer Peer
	conn net.Conn
	w    *bufio.Writer
	mu   sync.Mutex
}

func (c *Conn) Send(resp Response) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := json.NewEncoder(c.w).Encode(resp); err != nil {
		return err
	}
	return c.w.Flush()
}

func (c *Conn) Close() error { return c.conn.Close() }

// Handler answers one request. Long-lived subscriptions keep the Conn and send later.
type Handler func(ctx context.Context, c *Conn, req Request) Response

type Server struct {
	path    string
	mode    os.FileMode
	handler Handler
	ln      net.Listener
}

func NewServer(path string, mode os.FileMode, handler Handler) *Server {
	return &Server{path: path, mode: mode, handler: handler}
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	_ = os.Remove(s.path)
	ln, err := net.Listen("unix", s.path)
	if err != nil {
		return err
	}
	if err := os.Chmod(s.path, s.mode); err != nil {
		ln.Close()
		return err
	}
	s.ln = ln
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.serve(ctx, conn)
	}
}

func (s *Server) serve(ctx context.Context, raw net.Conn) {
	defer raw.Close()
	peer, err := peerOf(raw)
	if err != nil {
		return
	}
	c := &Conn{Peer: peer, conn: raw, w: bufio.NewWriter(raw)}
	scanner := bufio.NewScanner(raw)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		var req Request
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			_ = c.Send(Response{OK: false, Error: "bad request: " + err.Error()})
			continue
		}
		resp := s.handler(ctx, c, req)
		resp.ID = req.ID
		if resp.Error == "" && !resp.OK && resp.Payload == nil {
			continue // handler keeps the connection for a subscription
		}
		if err := c.Send(resp); err != nil {
			return
		}
	}
}

func peerOf(conn net.Conn) (Peer, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return Peer{}, errors.New("not a unix connection")
	}
	rawConn, err := uc.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var peer Peer
	var sysErr error
	err = rawConn.Control(func(fd uintptr) {
		cred, e := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if e != nil {
			sysErr = e
			return
		}
		peer.UID = int(cred.Uid)
		if cred.Ngroups > 0 {
			peer.GID = int(cred.Groups[0])
		}
		pid, e := unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		if e == nil {
			peer.PID = pid
		}
	})
	if err != nil {
		return Peer{}, err
	}
	return peer, sysErr
}

// Client makes one request and reads one response.
type Client struct {
	Path    string
	Timeout time.Duration
}

func (c Client) Call(reqType string, payload any, out any) error {
	conn, err := net.DialTimeout("unix", c.Path, c.Timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.Timeout))
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(conn).Encode(Request{Type: reqType, Payload: raw}); err != nil {
		return err
	}
	var resp Response
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("daemon: %s", resp.Error)
	}
	if out != nil && resp.Payload != nil {
		return json.Unmarshal(resp.Payload, out)
	}
	return nil
}

// Subscribe keeps a connection open and hands every message the daemon pushes to fn.
func (c Client) Subscribe(ctx context.Context, reqType string, payload any, fn func(Response) (reply any, err error)) error {
	conn, err := net.DialTimeout("unix", c.Path, c.Timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	go func() {
		<-ctx.Done()
		conn.Close()
	}()
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(conn)
	if err := enc.Encode(Request{Type: reqType, Payload: raw}); err != nil {
		return err
	}
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		var resp Response
		if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
			return err
		}
		reply, err := fn(resp)
		if err != nil {
			return err
		}
		if reply != nil {
			replyRaw, err := json.Marshal(reply)
			if err != nil {
				return err
			}
			if err := enc.Encode(Request{Type: "reply", ID: resp.ID, Payload: replyRaw}); err != nil {
				return err
			}
		}
	}
	if ctx.Err() != nil {
		return nil
	}
	return scanner.Err()
}
