package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/echtermeyer/overlord/internal/notify"
)

// Broker hands asks to whoever is subscribed (the notify agent of the logged-in user) and
// collects the answer. Without a subscriber an ask times out into its safe default.
type Broker struct {
	mu          sync.Mutex
	subscribers map[string]chan notify.Ask
	pending     map[string]chan notify.Answer
	timeout     time.Duration
}

func NewBroker(timeout time.Duration) *Broker {
	return &Broker{subscribers: map[string]chan notify.Ask{}, pending: map[string]chan notify.Answer{}, timeout: timeout}
}

func (b *Broker) Subscribe() (id string, ch <-chan notify.Ask, cancel func()) {
	id = newID()
	c := make(chan notify.Ask, 16)
	b.mu.Lock()
	b.subscribers[id] = c
	b.mu.Unlock()
	return id, c, func() {
		b.mu.Lock()
		delete(b.subscribers, id)
		b.mu.Unlock()
	}
}

func (b *Broker) Subscribers() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subscribers)
}

// Ask blocks until an answer arrives or the timeout passes; the zero choice means timeout.
func (b *Broker) Ask(ctx context.Context, a notify.Ask) (string, bool) {
	if a.ID == "" {
		a.ID = newID()
	}
	if a.Deadline.IsZero() {
		a.Deadline = time.Now().Add(b.timeout)
	}
	answer := make(chan notify.Answer, 1)
	b.mu.Lock()
	b.pending[a.ID] = answer
	subs := make([]chan notify.Ask, 0, len(b.subscribers))
	for _, c := range b.subscribers {
		subs = append(subs, c)
	}
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.pending, a.ID)
		b.mu.Unlock()
	}()
	for _, c := range subs {
		select {
		case c <- a:
		default:
		}
	}
	if len(subs) == 0 {
		return "", false
	}
	select {
	case ans := <-answer:
		return ans.Choice, true
	case <-time.After(time.Until(a.Deadline)):
		return "", false
	case <-ctx.Done():
		return "", false
	}
}

func (b *Broker) Answer(ans notify.Answer) bool {
	b.mu.Lock()
	ch, ok := b.pending[ans.ID]
	b.mu.Unlock()
	if !ok {
		return false
	}
	select {
	case ch <- ans:
	default:
	}
	return true
}

func newID() string {
	var buf [8]byte
	_, _ = rand.Read(buf[:])
	return hex.EncodeToString(buf[:])
}
