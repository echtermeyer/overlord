package daemon

import "github.com/echtermeyer/overlord/internal/notify"

func notifyAsk(title string) notify.Ask {
	return notify.Ask{Title: title, Options: []string{notify.Block, notify.AllowOnce, notify.AllowAlways}}
}

func answer(id, choice string) notify.Answer { return notify.Answer{ID: id, Choice: choice} }
