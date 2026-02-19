package utils

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
)

type ttyState struct {
	state  string
	logger Logger
}

// DisableCanonicalMode disables canonical mode on the terminal.
// This allows for reading single characters without pressing enter.
// The previous state is returned and can be used to restore the previous state.
// The optionalLogger can be used a preferred logger.
// If no optionalLogger is provided, a default logger is used.
//
// Usage in main.go: defer utils.RestoreTTY(utils.DisableCanonicalMode())
func DisableCanonicalMode(optionalLogger ...Logger) *ttyState {
	var l Logger = &defaultLogger{}
	if len(optionalLogger) > 0 {
		l = optionalLogger[0]
	}

	fh, err := os.OpenFile("/dev/tty", os.O_RDWR, 0666)
	if err != nil {
		l.Errorf("Could not open /dev/tty: %v", err)
		return nil
	}

	previousState := getSttyState(fh, l)

	// set new state: -icanon (disable canonical mode)
	if err := setSttyState(fh, &ttyState{
		state:  "-icanon",
		logger: l,
	}); err != nil {
		l.Warnf("Could not set stty state: %v", err)
		return nil
	}

	return previousState
}

// RestoreTTY restores the previous state of the terminal.
// The previous state is returned by DisableCanonicalMode.
// If the ttyState is nil, nothing is done.
func RestoreTTY(state *ttyState) {
	if state == nil {
		return
	}

	fh, err := os.OpenFile("/dev/tty", os.O_RDWR, 0666)
	if err != nil {
		state.logger.Errorf("Could not open /dev/tty: %v", err)
	}

	if err := setSttyState(fh, state); err != nil {
		state.logger.Warnf("Could not restore stty state: %v", err)
	}
}

func setSttyState(f *os.File, state *ttyState) error {
	outputBuf := new(bytes.Buffer)
	cmd := exec.Command("stty", state.state)
	cmd.Stdin = f
	cmd.Stdout = outputBuf
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func getSttyState(f *os.File, logger Logger) *ttyState {
	outputBuf := new(bytes.Buffer)
	cmd := exec.Command("stty", "-g")
	cmd.Stdin = f
	cmd.Stdout = outputBuf
	if err := cmd.Run(); err != nil {
		return &ttyState{
			state:  "",
			logger: logger,
		}
	}

	return &ttyState{
		state:  strings.TrimSuffix(outputBuf.String(), "\n"),
		logger: logger,
	}
}
