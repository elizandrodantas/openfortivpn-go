// Package userinput handles interactive password prompts and pinentry.
package userinput

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/term"
)

// ReadPassword prompts the user for a password. If pinentry is non-empty it
// delegates to the pinentry binary (Assuan protocol). Otherwise it reads from
// the terminal with echo disabled.
func ReadPassword(ctx context.Context, pinentry, hint, prompt string) (string, error) {
	if pinentry != "" {
		return readViaPinentry(ctx, pinentry, hint, prompt)
	}
	return readFromTerminal(prompt)
}

// ReadLine reads a single line from stdin (for OTP entry with echo enabled).
func ReadLine(prompt string) (string, error) {
	fmt.Print(prompt)
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		return strings.TrimSpace(scanner.Text()), nil
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("userinput: EOF reading line")
}

func readFromTerminal(prompt string) (string, error) {
	fmt.Print(prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("userinput: reading password: %w", err)
	}
	return string(b), nil
}

// readViaPinentry uses the Assuan protocol to request a password from a
// pinentry binary (e.g. pinentry-mac, pinentry-gtk-2).
func readViaPinentry(ctx context.Context, binary, hint, prompt string) (string, error) {
	cmd := exec.CommandContext(ctx, binary)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("userinput: pinentry stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("userinput: pinentry stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("userinput: starting pinentry %q: %w", binary, err)
	}
	defer cmd.Wait() //nolint:errcheck

	scanner := bufio.NewScanner(stdout)

	send := func(line string) error {
		_, err := fmt.Fprintln(stdin, line)
		return err
	}
	expect := func(prefix string) (string, error) {
		if !scanner.Scan() {
			return "", fmt.Errorf("userinput: pinentry EOF")
		}
		line := scanner.Text()
		if strings.HasPrefix(line, "ERR ") {
			return "", fmt.Errorf("userinput: pinentry error: %s", line)
		}
		if !strings.HasPrefix(line, prefix) {
			return "", fmt.Errorf("userinput: pinentry unexpected response: %q", line)
		}
		return line, nil
	}

	if _, err := expect("OK"); err != nil {
		return "", err
	}
	if hint != "" {
		if err := send("SETTITLE " + hint); err != nil {
			return "", err
		}
		if _, err := expect("OK"); err != nil {
			return "", err
		}
	}
	if prompt != "" {
		if err := send("SETPROMPT " + prompt); err != nil {
			return "", err
		}
		if _, err := expect("OK"); err != nil {
			return "", err
		}
	}
	if err := send("GETPIN"); err != nil {
		return "", err
	}
	line, err := expect("D ")
	if err != nil {
		return "", err
	}
	if _, err := expect("OK"); err != nil {
		return "", err
	}
	stdin.Close()
	return strings.TrimPrefix(line, "D "), nil
}
