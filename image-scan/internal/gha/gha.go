// Package gha holds the GitHub Actions plumbing: workflow commands on the log, step outputs and the job summary.
package gha

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

// Logger prints workflow commands (::error::, ::warning::, ...) and plain lines.
type Logger struct {
	w io.Writer
}

func NewLogger(w io.Writer) *Logger { return &Logger{w: w} }

func (l *Logger) Printf(format string, args ...any) { fmt.Fprintf(l.w, format+"\n", args...) }
func (l *Logger) Println(s string)                  { fmt.Fprintln(l.w, s) }
func (l *Logger) Errorf(format string, args ...any) { l.command("error", format, args...) }
func (l *Logger) Warningf(format string, args ...any) {
	l.command("warning", format, args...)
}
func (l *Logger) Noticef(format string, args ...any) { l.command("notice", format, args...) }
func (l *Logger) Debugf(format string, args ...any)  { l.command("debug", format, args...) }

// Command prints a workflow command of the given level (error, warning, notice or debug).
func (l *Logger) Command(level, format string, args ...any) { l.command(level, format, args...) }

func (l *Logger) Group(title string) { fmt.Fprintf(l.w, "::group::%s\n", title) }
func (l *Logger) EndGroup()          { fmt.Fprintln(l.w, "::endgroup::") }

func (l *Logger) command(level, format string, args ...any) {
	fmt.Fprintf(l.w, "::%s::%s\n", level, fmt.Sprintf(format, args...))
}

// Files are the files the runner reads the outputs and the summary of a step from.
type Files struct {
	Output  string // $GITHUB_OUTPUT
	Summary string // $GITHUB_STEP_SUMMARY
}

// SetOutput appends a step output, a heredoc when the value spans several lines.
func (f Files) SetOutput(name, value string) error {
	if f.Output == "" {
		return fmt.Errorf("GITHUB_OUTPUT is not set")
	}
	var entry string
	if strings.Contains(value, "\n") {
		delimiter := "EOF_" + randomHex()
		entry = fmt.Sprintf("%s<<%s\n%s\n%s\n", name, delimiter, value, delimiter)
	} else {
		entry = fmt.Sprintf("%s=%s\n", name, value)
	}
	return appendFile(f.Output, entry)
}

// AppendSummary appends markdown to the job summary.
func (f Files) AppendSummary(markdown string) error {
	if f.Summary == "" {
		return fmt.Errorf("GITHUB_STEP_SUMMARY is not set")
	}
	return appendFile(f.Summary, markdown)
}

func appendFile(path, content string) error {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := file.WriteString(content); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func randomHex() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// OneLine makes a message safe for a workflow command: a newline would end it.
func OneLine(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	return strings.ReplaceAll(s, "\n", " ")
}
