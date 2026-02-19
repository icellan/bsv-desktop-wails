package utils

// SafeClose is a helper function that closes a channel and returns.
// It is safe to use with closed channels.
// It uses go generics to allow for any type of channel.
func SafeClose[T any](ch chan T) {
	defer func() {
		_ = recover()
	}()

	close(ch)
}
