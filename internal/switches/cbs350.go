// Package switches handles SSH scans of Cisco CBS350 switches.
//
// CBS350 (small business) has non-standard SSH behavior:
//   - Requires `auth_none` initially (no password in SSH handshake)
//   - Then shell login via "User Name:" / "Password:" prompts
//   - Uses old algorithms: diffie-hellman-group14-sha1, ssh-rsa
//   - Paged output via "More:" — press space to continue
//
// This module ports the Python paramiko-based implementation from
// ../../../IT Monitoring/Agent/dekrimtexel-agent/tools/switch_config.py.
package switches

import (
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHClient wraps a live SSH session to a CBS350 switch.
type SSHClient struct {
	Client  *ssh.Client
	Session *ssh.Session
	stdin   io.WriteCloser
	stdout  io.Reader
	ch      chan readChunk // single read channel filled by one readLoop goroutine
	done    chan struct{}  // signals readLoop to exit
}

// Connect opens an SSH connection to a CBS350 switch using the non-standard
// auth_none + shell-login flow. Returns a ready-to-use SSHClient.
func Connect(host, username, password string, timeout time.Duration) (*SSHClient, error) {
	if !strings.Contains(host, ":") {
		host = host + ":22"
	}

	cfg := &ssh.ClientConfig{
		User: username,
		// auth_none first — CBS350 wants us to authenticate via the shell prompt
		Auth: []ssh.AuthMethod{
			ssh.RetryableAuthMethod(ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
				// Some devices present a keyboard-interactive prompt; answer with empty strings.
				answers := make([]string, len(questions))
				return answers, nil
			}), 1),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
		// Older algorithms required for CBS350
		Config: ssh.Config{
			KeyExchanges: []string{"diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1", "curve25519-sha256", "curve25519-sha256@libssh.org"},
			Ciphers:      []string{"aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-cbc", "3des-cbc"},
			MACs:         []string{"hmac-sha1", "hmac-sha2-256"},
		},
		HostKeyAlgorithms: []string{"ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256"},
	}

	conn, err := net.DialTimeout("tcp", host, timeout)
	if err != nil {
		return nil, fmt.Errorf("tcp dial %s: %w", host, err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, host, cfg)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ssh handshake: %w", err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)

	session, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("new session: %w", err)
	}

	// Request a PTY with width 200 so the paging is predictable
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("vt100", 50, 200, modes); err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("request pty: %w", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}

	if err := session.Shell(); err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("shell: %w", err)
	}

	c := &SSHClient{
		Client:  client,
		Session: session,
		stdin:   stdin,
		stdout:  stdout,
		ch:      make(chan readChunk, 32),
		done:    make(chan struct{}),
	}
	// Start the single read loop that all subsequent operations consume from
	go c.readLoop()

	// Wait for username prompt — CBS350 varianten: "User Name:", "Username:"
	if err := c.readUntilAny([]string{"User Name:", "Username:", "login:"}, 10*time.Second); err != nil {
		c.Close()
		return nil, fmt.Errorf("wait for user prompt: %w", err)
	}
	if _, err := c.stdin.Write([]byte(username + "\n")); err != nil {
		c.Close()
		return nil, fmt.Errorf("write username: %w", err)
	}

	// Wait for password prompt
	if err := c.readUntilAny([]string{"Password:", "password:"}, 10*time.Second); err != nil {
		c.Close()
		return nil, fmt.Errorf("wait for password prompt: %w", err)
	}
	if _, err := c.stdin.Write([]byte(password + "\n")); err != nil {
		c.Close()
		return nil, fmt.Errorf("write password: %w", err)
	}

	// Wait for '#' prompt (indicates we're logged in to privileged mode)
	if err := c.readUntil("#", 15*time.Second); err != nil {
		c.Close()
		return nil, fmt.Errorf("wait for # prompt (login may have failed): %w", err)
	}

	return c, nil
}

// Close ends the SSH session and tcp connection.
func (c *SSHClient) Close() {
	if c.done != nil {
		select {
		case <-c.done:
			// already closed
		default:
			close(c.done)
		}
	}
	if c.Session != nil {
		c.Session.Close()
	}
	if c.Client != nil {
		c.Client.Close()
	}
}

// readChunk represents one chunk of bytes read from stdout, or an error.
type readChunk struct {
	data []byte
	err  error
}

// readLoop runs in a single goroutine for the lifetime of the SSHClient,
// pumping bytes from stdout into c.ch. Multiple operations (Run, readUntil)
// consume from this channel sequentially. Exits when the session closes
// or c.done is closed.
func (c *SSHClient) readLoop() {
	defer close(c.ch)
	buf := make([]byte, 4096)
	for {
		select {
		case <-c.done:
			return
		default:
		}
		n, err := c.stdout.Read(buf)
		if n > 0 {
			cp := make([]byte, n)
			copy(cp, buf[:n])
			select {
			case c.ch <- readChunk{data: cp}:
			case <-c.done:
				return
			}
		}
		if err != nil {
			select {
			case c.ch <- readChunk{err: err}:
			case <-c.done:
			}
			return
		}
	}
}

// Run sends a single show command and returns the full output (handles paging).
//
// Detection strategy: inactivity-based. After sending the command we read until
// the channel has been silent for `inactivityTimeout`. This is more robust than
// prompt-detection because CBS350 sometimes prints extra newlines, ANSI escape
// codes, or otherwise breaks the "ends with #" assumption.
//
// Paging is handled by detecting "More:" / "--More--" in any chunk and sending
// a space character to advance.
func (c *SSHClient) Run(cmd string, timeout time.Duration) (string, error) {
	if _, err := c.stdin.Write([]byte(cmd + "\n")); err != nil {
		return "", fmt.Errorf("write cmd: %w", err)
	}

	const inactivityTimeout = 2 * time.Second

	var collected strings.Builder
	overallDeadline := time.NewTimer(timeout)
	defer overallDeadline.Stop()

	// Drain initial 1s burst — give the switch time to start sending
	initialBurstDone := time.NewTimer(1 * time.Second)
	for draining := true; draining; {
		select {
		case <-initialBurstDone.C:
			draining = false
		case chunk, ok := <-c.ch:
			if !ok {
				return cleanOutput(cmd, collected.String()), nil
			}
			if chunk.err == nil {
				collected.Write(chunk.data)
				data := string(chunk.data)
				if strings.Contains(data, "More:") || strings.Contains(data, "--More--") {
					c.stdin.Write([]byte(" "))
				}
			}
		}
	}

	// Now read until inactivity or overall timeout
	for {
		select {
		case <-overallDeadline.C:
			return cleanOutput(cmd, collected.String()), nil
		case <-time.After(inactivityTimeout):
			// No data for `inactivityTimeout` — assume command is done
			return cleanOutput(cmd, collected.String()), nil
		case chunk, ok := <-c.ch:
			if !ok {
				return cleanOutput(cmd, collected.String()), nil
			}
			if chunk.err != nil {
				if chunk.err == io.EOF {
					return cleanOutput(cmd, collected.String()), nil
				}
				return collected.String(), fmt.Errorf("read: %w", chunk.err)
			}
			collected.Write(chunk.data)
			data := string(chunk.data)
			if strings.Contains(data, "More:") || strings.Contains(data, "--More--") {
				c.stdin.Write([]byte(" "))
			}
		}
	}
}

// readUntilAny reads stdout until any of the given markers is seen or timeout.
// Returns nil on success (first matched marker was found).
func (c *SSHClient) readUntilAny(markers []string, timeout time.Duration) error {
	var collected strings.Builder
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	for {
		select {
		case <-deadline.C:
			return fmt.Errorf("none of markers %v found within %s (got: %q)", markers, timeout, collected.String())
		case chunk, ok := <-c.ch:
			if !ok {
				return fmt.Errorf("connection closed before markers %v", markers)
			}
			if chunk.err != nil && chunk.err != io.EOF {
				return chunk.err
			}
			collected.Write(chunk.data)
			s := collected.String()
			for _, m := range markers {
				if strings.Contains(s, m) {
					return nil
				}
			}
			if chunk.err == io.EOF {
				return fmt.Errorf("connection closed, none of %v found (got: %q)", markers, collected.String())
			}
		}
	}
}

// readUntil reads stdout until `marker` is seen or timeout.
func (c *SSHClient) readUntil(marker string, timeout time.Duration) error {
	var collected strings.Builder
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	for {
		select {
		case <-deadline.C:
			return fmt.Errorf("marker %q not found within %s (got: %q)", marker, timeout, collected.String())
		case chunk, ok := <-c.ch:
			if !ok {
				return fmt.Errorf("connection closed before marker %q (got: %q)", marker, collected.String())
			}
			if chunk.err != nil && chunk.err != io.EOF {
				return chunk.err
			}
			collected.Write(chunk.data)
			if strings.Contains(collected.String(), marker) {
				return nil
			}
			if chunk.err == io.EOF {
				return fmt.Errorf("connection closed before marker %q (got: %q)", marker, collected.String())
			}
		}
	}
}

var moreMarker = regexp.MustCompile(`--More--[\x08 ]*`)

// cleanOutput strips the command echo and trailing prompt from SSH output.
func cleanOutput(cmd, s string) string {
	// Remove --More-- artifacts
	s = moreMarker.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "\x08", "")

	lines := strings.Split(s, "\n")
	// Drop first line if it contains the command (echo)
	if len(lines) > 0 && strings.Contains(lines[0], cmd) {
		lines = lines[1:]
	}
	// Drop last line if it's a prompt
	if len(lines) > 0 {
		last := strings.TrimSpace(lines[len(lines)-1])
		if strings.HasSuffix(last, "#") || strings.HasSuffix(last, ">") {
			lines = lines[:len(lines)-1]
		}
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

// isTimeout returns true for net.Error timeouts (from SetDeadline).
func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if ne, ok := err.(net.Error); ok {
		return ne.Timeout()
	}
	return strings.Contains(err.Error(), "i/o timeout") || strings.Contains(err.Error(), "deadline exceeded")
}
