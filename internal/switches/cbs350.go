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
	}

	// Wait for "User Name:" prompt and answer
	if err := c.readUntil("User Name:", 10*time.Second); err != nil {
		c.Close()
		return nil, fmt.Errorf("wait for user prompt: %w", err)
	}
	if _, err := c.stdin.Write([]byte(username + "\n")); err != nil {
		c.Close()
		return nil, fmt.Errorf("write username: %w", err)
	}

	// Wait for "Password:" and answer
	if err := c.readUntil("Password:", 10*time.Second); err != nil {
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
	if c.Session != nil {
		c.Session.Close()
	}
	if c.Client != nil {
		c.Client.Close()
	}
}

// Run sends a single show command and returns the full output (handles paging).
// Blocks until we see another prompt marker ('#' at end of line) or timeout.
func (c *SSHClient) Run(cmd string, timeout time.Duration) (string, error) {
	if _, err := c.stdin.Write([]byte(cmd + "\n")); err != nil {
		return "", fmt.Errorf("write cmd: %w", err)
	}

	buf := make([]byte, 4096)
	var collected strings.Builder
	deadline := time.Now().Add(timeout)

	// Read until prompt or timeout
	for time.Now().Before(deadline) {
		c.Client.Conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := c.stdout.Read(buf)
		if n > 0 {
			chunk := string(buf[:n])
			collected.WriteString(chunk)

			// Handle paging
			if strings.Contains(chunk, "More:") || strings.Contains(chunk, "--More--") {
				c.stdin.Write([]byte(" "))
				continue
			}
			// Check for prompt ending the output
			s := collected.String()
			lines := strings.Split(strings.TrimRight(s, " \r\n"), "\n")
			if len(lines) > 0 {
				last := strings.TrimSpace(lines[len(lines)-1])
				if strings.HasSuffix(last, "#") || strings.HasSuffix(last, ">") {
					// Strip command echo (first line) and prompt (last line)
					return cleanOutput(cmd, s), nil
				}
			}
		}
		if err != nil && err != io.EOF {
			// Ignore timeout errors, keep reading
			if !isTimeout(err) {
				return collected.String(), fmt.Errorf("read: %w", err)
			}
		}
	}
	return collected.String(), fmt.Errorf("timeout waiting for prompt after %s", cmd)
}

// readUntil reads stdout until `marker` is seen or timeout.
func (c *SSHClient) readUntil(marker string, timeout time.Duration) error {
	buf := make([]byte, 1024)
	var collected strings.Builder
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c.Client.Conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := c.stdout.Read(buf)
		if n > 0 {
			collected.Write(buf[:n])
			if strings.Contains(collected.String(), marker) {
				return nil
			}
		}
		if err != nil && err != io.EOF && !isTimeout(err) {
			return err
		}
	}
	return fmt.Errorf("marker %q not found within %s (got: %q)", marker, timeout, collected.String())
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
