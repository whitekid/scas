package helper

import (
	"context"
	"os"
	"os/exec"
	"strings"

	"github.com/whitekid/goxp/log"
)

var (
	loggerExec = log.New(log.AddCallerSkip(1))
)

func Execute(command ...string) *Executer { return &Executer{command: command} }

type Executer struct {
	shell   bool
	command []string
	dir     string
}

func (exc *Executer) Shell() *Executer         { exc.shell = true; return exc }
func (exc *Executer) NoShell() *Executer       { exc.shell = false; return exc }
func (exc *Executer) Dir(dir string) *Executer { exc.dir = dir; return exc }

func (exc *Executer) buildCmd(ctx context.Context) *exec.Cmd {
	var name string
	var args []string

	if exc.shell {
		name = "sh"
		args = append([]string{"-c"}, exc.command...)
	} else if len(exc.command) > 0 {
		name = exc.command[0]

		if len(exc.command) > 1 {
			args = exc.command[1:]
		} else {
			args = nil
		}
	}

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = exc.dir

	return cmd
}

// Do execute command, output stdout to stdout and stderr to stderr
func (exc *Executer) Do(ctx context.Context) error {
	dir := exc.dir
	if dir == "" {
		dir, _ = os.Getwd()
	}
	loggerExec.Debugf("execute: %s", strings.Join(exc.command, " "))
	loggerExec.Debugf("dir: %s", dir)

	cmd := exc.buildCmd(ctx)

	cmd.Stderr = os.Stdout
	cmd.Stdout = os.Stderr

	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

// Output run command and return stdout
func (exc *Executer) Output(ctx context.Context) ([]byte, error) {
	dir := exc.dir
	if dir == "" {
		dir, _ = os.Getwd()
	}
	loggerExec.Debugf("execute: %s", strings.Join(exc.command, " "))
	loggerExec.Debugf("dir: %s", dir)

	return exc.buildCmd(ctx).Output()
}
