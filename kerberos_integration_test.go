package winrm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/otuschhoff/gokrb5/v8/keytab"
)

type kerberosComparisonResult struct {
	Client         string                  `json:"client"`
	Success        bool                    `json:"success"`
	ExitCode       int                     `json:"exit_code"`
	Stdout         string                  `json:"stdout"`
	Stderr         string                  `json:"stderr"`
	HTTPStatus     int                     `json:"http_status"`
	ErrorKind      string                  `json:"error_kind"`
	Error          string                  `json:"error"`
	Endpoint       string                  `json:"endpoint"`
	ProtectionMode string                  `json:"protection_mode"`
	RuntimeVersion string                  `json:"runtime_version"`
	ClientVersion  string                  `json:"client_version"`
	Outcome        string                  `json:"outcome"`
	Results        []kerberosCommandResult `json:"results,omitempty"`
}

type kerberosCommandScenario struct {
	Name      string `json:"name"`
	Command   string `json:"command"`
	Stdin     string `json:"stdin,omitempty"`
	SendStdin bool   `json:"send_stdin,omitempty"`
}

type kerberosCommandResult struct {
	Name     string `json:"name"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
}

func TestKerberosIntegration(t *testing.T) {
	if os.Getenv("WINRM_KERBEROS_INTEGRATION") != "1" {
		t.Skip("set WINRM_KERBEROS_INTEGRATION=1 to run")
	}

	host, realm, expectedHostname := kerberosIntegrationTarget(t)
	requirePasswordMode(t)
	username, password := passwordTestCredentials(t, realm)
	result := runGoKerberosComparison(host, realm, username, password, "")
	logComparisonResult(t, result)
	if !result.Success {
		t.Logf("native Kerberos detail: %s", result.Error)
		t.Fatalf("native Kerberos WinRM connection failed: %s", sanitizedOutcome(result))
	}
	assertComparisonResult(t, result, expectedHostname)
}

func TestKerberosComparisonWithPywinrm(t *testing.T) {
	if os.Getenv("WINRM_KERBEROS_COMPARISON") != "1" {
		t.Skip("set WINRM_KERBEROS_COMPARISON=1 to compare Go with pywinrm")
	}

	host, realm, expectedHostname := kerberosIntegrationTarget(t)
	requirePasswordMode(t)
	username, password := passwordTestCredentials(t, realm)
	principal := username + "@" + realm

	goResult := runGoKerberosComparison(host, realm, username, password, "")
	pythonResult := runPywinrmComparison(t, host, expectedHostname, principal, "", "password")
	logComparisonResult(t, goResult)
	logComparisonResult(t, pythonResult)
	if !goResult.Success || !pythonResult.Success {
		t.Fatalf("success parity requires both clients to succeed: Go=%s Python=%s", sanitizedOutcome(goResult), sanitizedOutcome(pythonResult))
	}
	assertComparisonResult(t, goResult, expectedHostname)
	assertComparisonResult(t, pythonResult, expectedHostname)
	if goResult.ExitCode != pythonResult.ExitCode || !strings.EqualFold(goResult.Stdout, pythonResult.Stdout) {
		t.Fatalf("clients returned different successful command results: Go=%s Python=%s", sanitizedOutcome(goResult), sanitizedOutcome(pythonResult))
	}
}

func TestKerberosPhase4ComparisonWithPywinrm(t *testing.T) {
	if os.Getenv("WINRM_KERBEROS_PHASE4_COMPARISON") != "1" {
		t.Skip("set WINRM_KERBEROS_PHASE4_COMPARISON=1 to compare command/session behavior with pywinrm")
	}

	host, realm, expectedHostname := kerberosIntegrationTarget(t)
	requirePasswordMode(t)
	username, password := passwordTestCredentials(t, realm)
	scenarios := kerberosPhase4Scenarios()
	goResult := runGoKerberosPhase4Comparison(host, realm, username, password, scenarios)
	pythonResult := runPywinrmPhase4Comparison(t, host, username+"@"+realm, scenarios)
	if !goResult.Success || !pythonResult.Success {
		t.Fatalf("Phase 4 parity requires both clients to succeed: Go=%s Python=%s", sanitizedOutcome(goResult), sanitizedOutcome(pythonResult))
	}
	assertKerberosPhase4Results(t, goResult.Results, expectedHostname)
	assertKerberosPhase4Results(t, pythonResult.Results, expectedHostname)
	if !reflect.DeepEqual(goResult.Results, pythonResult.Results) {
		t.Fatalf("Phase 4 command results differ between Go and Python")
	}
}

func TestKerberosComparisonDiagnostic(t *testing.T) {
	if os.Getenv("WINRM_KERBEROS_DIAGNOSTIC") != "1" {
		t.Skip("set WINRM_KERBEROS_DIAGNOSTIC=1 to compare failures diagnostically")
	}

	host, realm, expectedHostname := kerberosIntegrationTarget(t)
	authMode := envOrDefault("WINRM_KRB_AUTH", "password")
	username, password, keytabPath := kerberosTestCredentials(t, authMode, realm)
	goResult := runGoKerberosComparison(host, realm, username, password, keytabPath)
	pythonResult := runPywinrmComparison(t, host, expectedHostname, username+"@"+realm, keytabPath, authMode)
	logComparisonResult(t, goResult)
	logComparisonResult(t, pythonResult)
	if goResult.Success != pythonResult.Success || goResult.HTTPStatus != pythonResult.HTTPStatus || goResult.ErrorKind != pythonResult.ErrorKind {
		t.Fatalf("diagnostic outcomes differ: Go=%s Python=%s", sanitizedOutcome(goResult), sanitizedOutcome(pythonResult))
	}
}

func TestPywinrmIntegration(t *testing.T) {
	if os.Getenv("WINRM_PYWINRM_INTEGRATION") != "1" {
		t.Skip("set WINRM_PYWINRM_INTEGRATION=1 to run the pywinrm baseline")
	}

	host, realm, expectedHostname := kerberosIntegrationTarget(t)
	requirePasswordMode(t)
	username, _ := passwordTestCredentials(t, realm)
	result := runPywinrmComparison(t, host, expectedHostname, username+"@"+realm, "", "password")
	logComparisonResult(t, result)
	if !result.Success {
		t.Fatalf("pywinrm baseline failed: %s", sanitizedOutcome(result))
	}
	assertComparisonResult(t, result, expectedHostname)
}

func runGoKerberosComparison(host, realm, username, password, keytabPath string) kerberosComparisonResult {
	result := newGoComparisonResult(host)
	endpoint := NewEndpoint(host, 5985, false, false, nil, nil, nil, 15*time.Second)
	params := *DefaultParameters
	params.TransportDecorator = func() Transporter {
		return &ClientKerberos{
			Username: username, Password: password, Realm: realm,
			Hostname: host, Port: 5985, Proto: "http", SPN: "HTTP/" + host,
			KrbConf: envOrDefault("WINRM_KRB_CONFIG", "/etc/krb5.conf"), KrbKeytab: keytabPath,
		}
	}
	client, err := NewClientWithParameters(endpoint, username, password, &params)
	if err != nil {
		result.ErrorKind, result.Error = "setup", err.Error()
		return result
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result.Stdout, result.Stderr, result.ExitCode, err = client.RunCmdWithContext(ctx, "hostname")
	result.Stdout = trimTerminalLineEnding(result.Stdout)
	result.Stderr = trimTerminalLineEnding(result.Stderr)
	if err == nil {
		result.Success = result.ExitCode == 0
		if result.Success {
			result.Outcome = "success"
		}
		return result
	}
	result.Error = err.Error()
	var kerberosError *KerberosError
	if errors.As(err, &kerberosError) {
		result.HTTPStatus = kerberosError.StatusCode
		result.ErrorKind = "kerberos-" + kerberosError.Stage
		return result
	}
	if match := regexp.MustCompile(`request returned: (\d+)`).FindStringSubmatch(result.Error); len(match) == 2 {
		result.HTTPStatus, _ = strconv.Atoi(match[1])
	}
	if result.HTTPStatus == 401 {
		result.ErrorKind = "auth"
	} else {
		result.ErrorKind = "transport"
	}
	return result
}

func kerberosPhase4Scenarios() []kerberosCommandScenario {
	return []kerberosCommandScenario{
		{Name: "hostname-1", Command: "hostname"},
		{Name: "hostname-2", Command: "hostname"},
		{Name: "streams-and-exit", Command: `cmd.exe /d /s /c "(echo phase4-out)&(>&2 echo phase4-err)&exit /b 23"`},
		{Name: "powershell-unicode", Command: Powershell(`[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new(); [Console]::Write('phase4-日本語-€')`)},
		{Name: "stdin", Command: Powershell(`[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new(); [Console]::Write([Console]::In.ReadToEnd())`), Stdin: "phase4-stdin\r\n", SendStdin: true},
		{Name: "large-output", Command: Powershell(`[Console]::Write('x' * 200000)`)},
	}
}

func runGoKerberosPhase4Comparison(host, realm, username, password string, scenarios []kerberosCommandScenario) kerberosComparisonResult {
	result := newGoComparisonResult(host)
	endpoint := NewEndpoint(host, 5985, false, false, nil, nil, nil, 15*time.Second)
	params := *DefaultParameters
	params.TransportDecorator = func() Transporter {
		return &ClientKerberos{
			Username: username, Password: password, Realm: realm,
			Hostname: host, Port: 5985, Proto: "http", SPN: "HTTP/" + host,
			KrbConf: envOrDefault("WINRM_KRB_CONFIG", "/etc/krb5.conf"),
		}
	}
	client, err := NewClientWithParameters(endpoint, username, password, &params)
	if err != nil {
		result.ErrorKind, result.Error = "setup", err.Error()
		return result
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	for _, scenario := range scenarios {
		var stdout, stderr string
		var exitCode int
		if scenario.SendStdin {
			stdout, stderr, exitCode, err = client.RunWithContextWithString(ctx, scenario.Command, scenario.Stdin)
		} else {
			stdout, stderr, exitCode, err = client.RunCmdWithContext(ctx, scenario.Command)
		}
		if err != nil {
			result.ErrorKind, result.Error = "command", err.Error()
			return result
		}
		result.Results = append(result.Results, kerberosCommandResult{
			Name: scenario.Name, Stdout: stdout, Stderr: stderr, ExitCode: exitCode,
		})
	}
	result.Success = true
	result.Outcome = "success"
	return result
}

func runPywinrmPhase4Comparison(t *testing.T, host, principal string, scenarios []kerberosCommandScenario) kerberosComparisonResult {
	t.Helper()
	encodedScenarios, err := json.Marshal(scenarios)
	if err != nil {
		t.Fatal(err)
	}
	python := envOrDefault("WINRM_PYTHON", "python3")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, python, filepath.Join("development", "compare_pywinrm.py"))
	command.Env = mergeEnvironment(os.Environ(), map[string]string{
		"KRB5_CONFIG":             envOrDefault("WINRM_KRB_CONFIG", "/etc/krb5.conf"),
		"WINRM_HOST":              host,
		"WINRM_KRB_AUTH":          "password",
		"WINRM_KRB_PASSWORD_FILE": envOrDefault("WINRM_KRB_PASSWORD_FILE", "pw"),
		"WINRM_KRB_PRINCIPAL":     principal,
		"WINRM_KRB_SCENARIOS":     string(encodedScenarios),
	})
	output, err := command.Output()
	if err != nil {
		t.Fatalf("run pywinrm Phase 4 comparison: %v", err)
	}
	var result kerberosComparisonResult
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("decode pywinrm Phase 4 result: %v", err)
	}
	return result
}

func assertKerberosPhase4Results(t *testing.T, results []kerberosCommandResult, expectedHostname string) {
	t.Helper()
	if len(results) != 6 {
		t.Fatalf("got %d Phase 4 results, want 6", len(results))
	}
	for index := 0; index < 2; index++ {
		assertHostnameResult(t, results[index].Stdout, results[index].Stderr, results[index].ExitCode, expectedHostname)
	}
	if result := results[2]; result.ExitCode != 23 || trimTerminalLineEnding(result.Stdout) != "phase4-out" || trimTerminalLineEnding(result.Stderr) != "phase4-err" {
		t.Fatalf("streams-and-exit result is invalid: exit=%d stdout=%q stderr=%q", result.ExitCode, result.Stdout, result.Stderr)
	}
	if result := results[3]; result.ExitCode != 0 || result.Stdout != "phase4-日本語-€" || result.Stderr != "" {
		t.Fatalf("PowerShell Unicode result is invalid: exit=%d stdout=%q stderr=%q", result.ExitCode, result.Stdout, result.Stderr)
	}
	if result := results[4]; result.ExitCode != 0 || !strings.Contains(result.Stdout, "phase4-stdin") || result.Stderr != "" {
		t.Fatalf("stdin result is invalid: exit=%d stdout=%q stderr=%q", result.ExitCode, result.Stdout, result.Stderr)
	}
	if result := results[5]; result.ExitCode != 0 || len(result.Stdout) != 200000 || strings.Trim(result.Stdout, "x") != "" || result.Stderr != "" {
		t.Fatalf("large-output result is invalid: exit=%d stdout-bytes=%d stderr=%q", result.ExitCode, len(result.Stdout), result.Stderr)
	}
}

func newGoComparisonResult(host string) kerberosComparisonResult {
	return kerberosComparisonResult{
		Client: "go", ExitCode: -1, Endpoint: winRMEndpoint(host),
		ProtectionMode: "kerberos-encrypted-soap", RuntimeVersion: runtime.Version(),
		ClientVersion: gokrb5Version(), Outcome: "failure",
	}
}

func runPywinrmComparison(t *testing.T, host, expectedHostname, principal, keytabPath, authMode string) kerberosComparisonResult {
	t.Helper()
	python := envOrDefault("WINRM_PYTHON", "python3")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, python, filepath.Join("development", "compare_pywinrm.py"))
	command.Env = mergeEnvironment(os.Environ(), map[string]string{
		"KRB5_CONFIG":             envOrDefault("WINRM_KRB_CONFIG", "/etc/krb5.conf"),
		"WINRM_EXPECTED_HOSTNAME": expectedHostname,
		"WINRM_HOST":              host,
		"WINRM_KRB_AUTH":          authMode,
		"WINRM_KRB_KEYTAB":        keytabPath,
		"WINRM_KRB_PASSWORD_FILE": envOrDefault("WINRM_KRB_PASSWORD_FILE", "pw"),
		"WINRM_KRB_PRINCIPAL":     principal,
	})
	output, err := command.Output()
	if err != nil {
		t.Fatalf("run pywinrm comparison: %v", err)
	}
	var result kerberosComparisonResult
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("decode pywinrm result: %v", err)
	}
	if result.ErrorKind == "setup" {
		t.Fatalf("pywinrm setup failed: %s; install requirements-integration.txt", result.Error)
	}
	return result
}

func kerberosTestCredentials(t *testing.T, authMode, realm string) (username, password, keytabPath string) {
	t.Helper()

	switch authMode {
	case "keytab":
		keytabPath = envOrDefault("WINRM_KRB_KEYTAB", "krb5.keytab")
		kt, err := keytab.Load(keytabPath)
		if err != nil {
			t.Fatalf("load keytab: %v", err)
		}
		username, keytabRealm, err := firstKeytabPrincipal(kt)
		if err != nil {
			t.Fatal(err)
		}
		if keytabRealm != realm {
			t.Fatalf("keytab realm %q does not match configured realm %q", keytabRealm, realm)
		}
		return username, "", keytabPath
	case "password":
		username, password = passwordTestCredentials(t, realm)
		return username, password, ""
	default:
		t.Fatalf("unsupported WINRM_KRB_AUTH %q; use keytab or password", authMode)
		return "", "", ""
	}
}

func firstKeytabPrincipal(kt *keytab.Keytab) (string, string, error) {
	data, err := kt.JSON()
	if err != nil {
		return "", "", fmt.Errorf("encode keytab metadata: %w", err)
	}
	var metadata struct {
		Entries []struct {
			Principal struct {
				Realm      string
				Components []string
			}
		}
	}
	if err := json.Unmarshal([]byte(data), &metadata); err != nil {
		return "", "", fmt.Errorf("decode keytab metadata: %w", err)
	}
	if len(metadata.Entries) == 0 || len(metadata.Entries[0].Principal.Components) == 0 {
		return "", "", fmt.Errorf("keytab contains no principals")
	}
	principal := metadata.Entries[0].Principal
	return strings.Join(principal.Components, "/"), principal.Realm, nil
}

func passwordTestCredentials(t *testing.T, realm string) (string, string) {
	t.Helper()
	username, password, err := loadPasswordCredentials(
		envOrDefault("WINRM_KRB_USER_FILE", "user"),
		envOrDefault("WINRM_KRB_PASSWORD_FILE", "pw"),
		realm,
	)
	if err != nil {
		t.Fatal(err)
	}
	return username, password
}

func loadPasswordCredentials(userPath, passwordPath, realm string) (string, string, error) {
	principalBytes, err := os.ReadFile(userPath)
	if err != nil {
		return "", "", fmt.Errorf("read username file: %w", err)
	}
	passwordBytes, err := os.ReadFile(passwordPath)
	if err != nil {
		return "", "", fmt.Errorf("read password file: %w", err)
	}
	principal := strings.TrimSpace(trimTerminalLineEnding(string(principalBytes)))
	password := trimTerminalLineEnding(string(passwordBytes))
	if principal == "" {
		return "", "", errors.New("username must not be empty")
	}
	if password == "" {
		return "", "", errors.New("password must not be empty")
	}
	username, principalRealm, found := strings.Cut(principal, "@")
	if username == "" || strings.Contains(principalRealm, "@") {
		return "", "", errors.New("invalid Kerberos principal in username file")
	}
	if found && principalRealm == "" {
		return "", "", errors.New("Kerberos principal realm must not be empty")
	}
	if found && !strings.EqualFold(principalRealm, realm) {
		return "", "", fmt.Errorf("username realm does not match configured realm")
	}
	return username, password, nil
}

func trimTerminalLineEnding(value string) string {
	if strings.HasSuffix(value, "\r\n") {
		return strings.TrimSuffix(value, "\r\n")
	}
	return strings.TrimSuffix(value, "\n")
}

func requirePasswordMode(t *testing.T) {
	t.Helper()
	if authMode := os.Getenv("WINRM_KRB_AUTH"); authMode != "" && authMode != "password" {
		t.Fatalf("release gate requires WINRM_KRB_AUTH=password, got %q", authMode)
	}
}

func assertHostnameResult(t *testing.T, stdout, stderr string, exitCode int, expectedHostname string) {
	t.Helper()
	if err := validateHostnameResult(stdout, stderr, exitCode, expectedHostname); err != nil {
		t.Fatal(err)
	}
}

func validateHostnameResult(stdout, stderr string, exitCode int, expectedHostname string) error {
	if exitCode != 0 {
		return fmt.Errorf("hostname exited with code %d", exitCode)
	}
	if actual := strings.TrimSuffix(strings.TrimSuffix(stdout, "\n"), "\r"); !strings.EqualFold(actual, expectedHostname) {
		return fmt.Errorf("hostname stdout mismatch: got %q, want %q", actual, expectedHostname)
	}
	if stderr != "" {
		return fmt.Errorf("hostname stderr must be empty, got %q", stderr)
	}
	return nil
}

func assertComparisonResult(t *testing.T, result kerberosComparisonResult, expectedHostname string) {
	t.Helper()
	assertHostnameResult(t, result.Stdout, result.Stderr, result.ExitCode, expectedHostname)
}

func kerberosIntegrationTarget(t *testing.T) (host, realm, expectedHostname string) {
	t.Helper()
	host = strings.TrimSpace(os.Getenv("WINRM_HOST"))
	if host == "" {
		encoded, err := os.ReadFile("target")
		if err != nil {
			t.Fatalf("read target file: %v", err)
		}
		host = strings.TrimSpace(string(encoded))
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 || labels[0] == "" || strings.ContainsAny(host, " /\\") {
		t.Fatalf("target must be a fully qualified DNS name")
	}
	expectedHostname = labels[0]
	realm = strings.TrimSpace(os.Getenv("WINRM_KRB_REALM"))
	if realm == "" {
		realm = strings.ToUpper(strings.Join(labels[1:], "."))
	}
	return host, realm, expectedHostname
}

func winRMEndpoint(host string) string {
	return "http://" + host + ":5985/wsman"
}

func gokrb5Version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dependency := range info.Deps {
		if dependency.Path == "github.com/otuschhoff/gokrb5/v8" {
			return dependency.Version
		}
	}
	return "unknown"
}

func logComparisonResult(t *testing.T, result kerberosComparisonResult) {
	t.Helper()
	t.Logf("client=%s outcome=%s endpoint=%s protection=%s runtime=%s version=%s status=%d kind=%s", result.Client, result.Outcome, result.Endpoint, result.ProtectionMode, result.RuntimeVersion, result.ClientVersion, result.HTTPStatus, result.ErrorKind)
}

func sanitizedOutcome(result kerberosComparisonResult) string {
	return fmt.Sprintf("client=%s outcome=%s status=%d kind=%s", result.Client, result.Outcome, result.HTTPStatus, result.ErrorKind)
}

func mergeEnvironment(base []string, overrides map[string]string) []string {
	values := make(map[string]string, len(base)+len(overrides))
	for _, entry := range base {
		name, value, found := strings.Cut(entry, "=")
		if found {
			values[name] = value
		}
	}
	for name, value := range overrides {
		values[name] = value
	}
	environment := make([]string, 0, len(values))
	for name, value := range values {
		environment = append(environment, name+"="+value)
	}
	return environment
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func TestLoadPasswordCredentials(t *testing.T) {
	tests := []struct {
		name, principal, password, realm, wantUser, wantPassword string
		wantError                                                string
	}{
		{name: "plain username", principal: "alice\n", password: "secret\n", realm: "EXAMPLE.COM", wantUser: "alice", wantPassword: "secret"},
		{name: "qualified username CRLF", principal: "alice@example.com\r\n", password: " secret \r\n", realm: "EXAMPLE.COM", wantUser: "alice", wantPassword: " secret "},
		{name: "password without newline", principal: "alice", password: "secret", realm: "EXAMPLE.COM", wantUser: "alice", wantPassword: "secret"},
		{name: "remove one ending only", principal: "alice", password: "secret\n\n", realm: "EXAMPLE.COM", wantUser: "alice", wantPassword: "secret\n"},
		{name: "empty username", principal: "\n", password: "secret", realm: "EXAMPLE.COM", wantError: "username must not be empty"},
		{name: "empty password", principal: "alice", password: "\n", realm: "EXAMPLE.COM", wantError: "password must not be empty"},
		{name: "empty principal realm", principal: "alice@\n", password: "secret", realm: "EXAMPLE.COM", wantError: "realm must not be empty"},
		{name: "wrong principal realm", principal: "alice@OTHER.COM\n", password: "secret", realm: "EXAMPLE.COM", wantError: "does not match"},
		{name: "invalid principal", principal: "alice@EXAMPLE.COM@OTHER.COM", password: "secret", realm: "EXAMPLE.COM", wantError: "invalid Kerberos principal"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			userPath, passwordPath := filepath.Join(directory, "user"), filepath.Join(directory, "pw")
			if err := os.WriteFile(userPath, []byte(test.principal), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(passwordPath, []byte(test.password), 0o600); err != nil {
				t.Fatal(err)
			}
			username, password, err := loadPasswordCredentials(userPath, passwordPath, test.realm)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("error = %v, want containing %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if username != test.wantUser || password != test.wantPassword {
				t.Fatalf("credentials = (%q, %q), want (%q, %q)", username, password, test.wantUser, test.wantPassword)
			}
		})
	}
}

func TestLoadPasswordCredentialsMissingFiles(t *testing.T) {
	directory := t.TempDir()
	missing := filepath.Join(directory, "missing")
	userPath := filepath.Join(directory, "user")
	if _, _, err := loadPasswordCredentials(missing, missing, "EXAMPLE.COM"); err == nil || !strings.Contains(err.Error(), "username file") {
		t.Fatalf("missing username error = %v", err)
	}
	if err := os.WriteFile(userPath, []byte("alice"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadPasswordCredentials(userPath, missing, "EXAMPLE.COM"); err == nil || !strings.Contains(err.Error(), "password file") {
		t.Fatalf("missing password error = %v", err)
	}
}

func TestMergeEnvironmentReplacesValues(t *testing.T) {
	environment := mergeEnvironment([]string{"KEEP=value", "KRB5_CONFIG=old", "KRB5_CONFIG=older"}, map[string]string{"KRB5_CONFIG": "new"})
	seen := make(map[string]string)
	for _, entry := range environment {
		name, value, found := strings.Cut(entry, "=")
		if !found {
			t.Fatalf("invalid environment entry %q", entry)
		}
		if _, duplicate := seen[name]; duplicate {
			t.Fatalf("duplicate environment key %q", name)
		}
		seen[name] = value
	}
	if seen["KRB5_CONFIG"] != "new" || seen["KEEP"] != "value" {
		t.Fatalf("merged environment = %#v", seen)
	}
}

func TestComparisonResultMetadata(t *testing.T) {
	result := newGoComparisonResult("127.0.0.1")
	if result.Client != "go" || result.Endpoint != "http://127.0.0.1:5985/wsman" {
		t.Fatalf("identity metadata = %#v", result)
	}
	if result.RuntimeVersion == "" || result.ClientVersion == "" || result.ProtectionMode == "" || result.Outcome == "" {
		t.Fatalf("incomplete metadata = %#v", result)
	}
}

func TestValidateHostnameResult(t *testing.T) {
	tests := []struct {
		name, stdout, stderr string
		exitCode             int
		wantError            string
	}{
		{name: "success", stdout: "host\r\n"},
		{name: "wrong hostname", stdout: "other", wantError: "stdout mismatch"},
		{name: "stderr", stdout: "host", stderr: "warning", wantError: "stderr must be empty"},
		{name: "exit code", stdout: "host", exitCode: 1, wantError: "exited with code 1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateHostnameResult(test.stdout, test.stderr, test.exitCode, "host")
			if test.wantError == "" && err != nil {
				t.Fatal(err)
			}
			if test.wantError != "" && (err == nil || !strings.Contains(err.Error(), test.wantError)) {
				t.Fatalf("error = %v, want containing %q", err, test.wantError)
			}
		})
	}
}
