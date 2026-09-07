package winrm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	Client         string `json:"client"`
	Success        bool   `json:"success"`
	ExitCode       int    `json:"exit_code"`
	Stdout         string `json:"stdout"`
	Stderr         string `json:"stderr"`
	HTTPStatus     int    `json:"http_status"`
	ErrorKind      string `json:"error_kind"`
	Error          string `json:"error"`
	Endpoint       string `json:"endpoint"`
	ProtectionMode string `json:"protection_mode"`
	RuntimeVersion string `json:"runtime_version"`
	ClientVersion  string `json:"client_version"`
	Outcome        string `json:"outcome"`
}

const (
	kerberosIntegrationHost  = "win-host.example.com"
	kerberosExpectedHostname = "win-host"
	kerberosIntegrationRealm = "EXAMPLE.COM"
)

func TestKerberosIntegration(t *testing.T) {
	if os.Getenv("WINRM_KERBEROS_INTEGRATION") != "1" {
		t.Skip("set WINRM_KERBEROS_INTEGRATION=1 to run")
	}

	host := envOrDefault("WINRM_HOST", kerberosIntegrationHost)
	realm := envOrDefault("WINRM_KRB_REALM", kerberosIntegrationRealm)
	requirePasswordMode(t)
	username, password := passwordTestCredentials(t, realm)
	result := runGoKerberosComparison(host, realm, username, password, "")
	logComparisonResult(t, result)
	if !result.Success {
		t.Fatalf("native Kerberos WinRM connection failed: %s", sanitizedOutcome(result))
	}
	assertComparisonResult(t, result)
}

func TestKerberosComparisonWithPywinrm(t *testing.T) {
	if os.Getenv("WINRM_KERBEROS_COMPARISON") != "1" {
		t.Skip("set WINRM_KERBEROS_COMPARISON=1 to compare Go with pywinrm")
	}

	host := envOrDefault("WINRM_HOST", kerberosIntegrationHost)
	realm := envOrDefault("WINRM_KRB_REALM", kerberosIntegrationRealm)
	requirePasswordMode(t)
	username, password := passwordTestCredentials(t, realm)
	principal := username + "@" + realm

	goResult := runGoKerberosComparison(host, realm, username, password, "")
	pythonResult := runPywinrmComparison(t, host, principal, "", "password")
	logComparisonResult(t, goResult)
	logComparisonResult(t, pythonResult)
	if !goResult.Success || !pythonResult.Success {
		t.Fatalf("success parity requires both clients to succeed: Go=%s Python=%s", sanitizedOutcome(goResult), sanitizedOutcome(pythonResult))
	}
	assertComparisonResult(t, goResult)
	assertComparisonResult(t, pythonResult)
	if goResult.ExitCode != pythonResult.ExitCode || !strings.EqualFold(goResult.Stdout, pythonResult.Stdout) {
		t.Fatalf("clients returned different successful command results: Go=%s Python=%s", sanitizedOutcome(goResult), sanitizedOutcome(pythonResult))
	}
}

func TestKerberosComparisonDiagnostic(t *testing.T) {
	if os.Getenv("WINRM_KERBEROS_DIAGNOSTIC") != "1" {
		t.Skip("set WINRM_KERBEROS_DIAGNOSTIC=1 to compare failures diagnostically")
	}

	host := envOrDefault("WINRM_HOST", kerberosIntegrationHost)
	realm := envOrDefault("WINRM_KRB_REALM", kerberosIntegrationRealm)
	authMode := envOrDefault("WINRM_KRB_AUTH", "password")
	username, password, keytabPath := kerberosTestCredentials(t, authMode, realm)
	goResult := runGoKerberosComparison(host, realm, username, password, keytabPath)
	pythonResult := runPywinrmComparison(t, host, username+"@"+realm, keytabPath, authMode)
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

	host := envOrDefault("WINRM_HOST", kerberosIntegrationHost)
	realm := envOrDefault("WINRM_KRB_REALM", kerberosIntegrationRealm)
	requirePasswordMode(t)
	username, _ := passwordTestCredentials(t, realm)
	result := runPywinrmComparison(t, host, username+"@"+realm, "", "password")
	logComparisonResult(t, result)
	if !result.Success {
		t.Fatalf("pywinrm baseline failed: %s", sanitizedOutcome(result))
	}
	assertComparisonResult(t, result)
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

func newGoComparisonResult(host string) kerberosComparisonResult {
	return kerberosComparisonResult{
		Client: "go", ExitCode: -1, Endpoint: winRMEndpoint(host),
		ProtectionMode: "kerberos-plaintext-soap-unimplemented", RuntimeVersion: runtime.Version(),
		ClientVersion: gokrb5Version(), Outcome: "failure",
	}
}

func runPywinrmComparison(t *testing.T, host, principal, keytabPath, authMode string) kerberosComparisonResult {
	t.Helper()
	python := envOrDefault("WINRM_PYTHON", "python3")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, python, filepath.Join("development", "compare_pywinrm.py"))
	command.Env = mergeEnvironment(os.Environ(), map[string]string{
		"KRB5_CONFIG":             envOrDefault("WINRM_KRB_CONFIG", "/etc/krb5.conf"),
		"WINRM_EXPECTED_HOSTNAME": kerberosExpectedHostname,
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

func assertHostnameResult(t *testing.T, stdout, stderr string, exitCode int) {
	t.Helper()
	if err := validateHostnameResult(stdout, stderr, exitCode); err != nil {
		t.Fatal(err)
	}
}

func validateHostnameResult(stdout, stderr string, exitCode int) error {
	if exitCode != 0 {
		return fmt.Errorf("hostname exited with code %d", exitCode)
	}
	if actual := strings.TrimSuffix(strings.TrimSuffix(stdout, "\n"), "\r"); !strings.EqualFold(actual, kerberosExpectedHostname) {
		return fmt.Errorf("hostname stdout mismatch: got %q, want %q", actual, kerberosExpectedHostname)
	}
	if stderr != "" {
		return fmt.Errorf("hostname stderr must be empty, got %q", stderr)
	}
	return nil
}

func assertComparisonResult(t *testing.T, result kerberosComparisonResult) {
	t.Helper()
	assertHostnameResult(t, result.Stdout, result.Stderr, result.ExitCode)
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
		{name: "success", stdout: "win-host\r\n"},
		{name: "wrong hostname", stdout: "other", wantError: "stdout mismatch"},
		{name: "stderr", stdout: "win-host", stderr: "warning", wantError: "stderr must be empty"},
		{name: "exit code", stdout: "win-host", exitCode: 1, wantError: "exited with code 1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateHostnameResult(test.stdout, test.stderr, test.exitCode)
			if test.wantError == "" && err != nil {
				t.Fatal(err)
			}
			if test.wantError != "" && (err == nil || !strings.Contains(err.Error(), test.wantError)) {
				t.Fatalf("error = %v, want containing %q", err, test.wantError)
			}
		})
	}
}
