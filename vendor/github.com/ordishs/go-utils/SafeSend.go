package utils

import (
	"log"
	"time"
)

// SafeSend is a helper function that sends a value on a channel and returns.
// It is safe to use with closed channels.
// It uses go generics to allow for any type of channel.
func SafeSend[T any](ch chan T, t T, timeoutOption ...time.Duration) bool {
	defer func() {
		_ = recover()
	}()

	if len(timeoutOption) == 0 {
		ch <- t
		return true
	}

	for {
		timer := time.NewTimer(timeoutOption[0])
		select {
		case <-timer.C:
			log.Printf("SafeSend: failed to process message on channel after %s. retrying value: %#v", timeoutOption[0], t)
		case ch <- t:
			return true
		}
	}
}
