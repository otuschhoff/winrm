package main

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestCLIProcess(t *testing.T) {
	if os.Getenv("WINRM_CLI_TEST_PROCESS") != "1" {
		t.Skip("subprocess helper")
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"winrm"}, os.Args[i+1:]...)
			main()
			return
		}
	}
	t.Fatal("missing subprocess argument separator")
}

func TestPowerShellPromptIntegration(t *testing.T) {
	if os.Getenv("WINRM_CLI_INTEGRATION") != "1" {
		t.Skip("set WINRM_CLI_INTEGRATION=1 and supply WINRM_HOST, WINRM_USER, and credentials")
	}
	host, username := os.Getenv("WINRM_HOST"), os.Getenv("WINRM_USER")
	if host == "" || username == "" {
		t.Fatal("WINRM_HOST and WINRM_USER are required")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"default", "nested"} {
		t.Run(mode, func(t *testing.T) {
			args := []string{"-test.run=^TestCLIProcess$", "--"}
			if mode == "nested" {
				args = append(args, "-cmd")
			}
			if passwordFile := os.Getenv("WINRM_PASSWORD_FILE"); passwordFile != "" {
				args = append(args, "-password-file", passwordFile)
			}
			if realm := os.Getenv("WINRM_KRB_REALM"); realm != "" {
				args = append(args, "-realm", realm)
			}
			if configuration := os.Getenv("WINRM_KRB_CONFIG"); configuration != "" {
				args = append(args, "-krb-config", configuration)
			}
			args = append(args, username+"@"+host)
			cmd := exec.Command(executable, args...)
			cmd.Env = append(os.Environ(), "WINRM_CLI_TEST_PROCESS=1")
			input, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			output, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if cmd.ProcessState == nil {
					if err := cmd.Process.Signal(os.Interrupt); err != nil {
						t.Errorf("interrupt test client: %v", err)
					}
					_ = input.Close()
					if err := cmd.Wait(); err != nil {
						t.Log("test client interrupted during cleanup")
					}
				}
			})
			chunks := make(chan []byte, 32)
			go func() {
				defer close(chunks)
				buf := make([]byte, 4096)
				for {
					n, err := output.Read(buf)
					if n > 0 {
						chunks <- append([]byte(nil), buf[:n]...)
					}
					if err != nil {
						return
					}
				}
			}()
			var received []byte
			await := func(text string, limit time.Duration) {
				t.Helper()
				timer := time.NewTimer(limit)
				defer timer.Stop()
				for !bytes.Contains(received, []byte(text)) {
					select {
					case chunk, ok := <-chunks:
						if !ok {
							t.Fatal("client output ended before expected prompt or command result")
						}
						received = append(received, chunk...)
					case <-timer.C:
						t.Fatalf("expected prompt or command result not received within %s", limit)
					}
				}
				received = nil
			}
			send := func(line string) {
				t.Helper()
				if _, err := io.WriteString(input, line+"\n"); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "nested" {
				await(">", 10*time.Second)
				send("powershell")
			}
			await("PS ", 10*time.Second)
			send(`Write-Output ("PROMPT_TEST_" + "RESPONSIVE")`)
			await("PROMPT_TEST_RESPONSIVE", 5*time.Second)
			send(`$winrmPromptTest = "PROMPT_TEST_" + "PERSISTENT"`)
			send("Write-Output $winrmPromptTest")
			await("PROMPT_TEST_PERSISTENT", 5*time.Second)
			send("exit 0")
			if mode == "nested" {
				send("exit /b 0")
			}
			if err := input.Close(); err != nil {
				t.Fatal(err)
			}
			// Drain remaining output before Wait closes the process pipes.
			exitTimer := time.NewTimer(10 * time.Second)
			defer exitTimer.Stop()
		drain:
			for {
				select {
				case _, ok := <-chunks:
					if !ok {
						break drain
					}
				case <-exitTimer.C:
					t.Fatal("client did not close output within ten seconds of exit")
				}
			}
			if err := cmd.Wait(); err != nil {
				t.Fatal("test client did not exit successfully")
			}
			if strings.TrimSpace(stderr.String()) != "" {
				t.Fatal("test client produced unexpected stderr")
			}
		})
	}
}
