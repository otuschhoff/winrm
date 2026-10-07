package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/winrm"
)

type options struct {
	host, user, auth, realm, krbConfig, ccache, passwordFile string
	caFile, shell, command                                   string
	port                                                     int
	https                                                    bool
	timeout                                                  time.Duration
}

func parseOptions(args []string, stderr io.Writer) (options, error) {
	var o options
	flags := flag.NewFlagSet("winrm", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&o.host, "host", "", "remote Windows hostname (required)")
	flags.StringVar(&o.user, "user", "", "username or user@REALM")
	flags.StringVar(&o.auth, "auth", "kerberos", "authentication: kerberos or basic (requires HTTPS)")
	flags.StringVar(&o.realm, "realm", "", "Kerberos realm (defaults to user realm or krb5.conf)")
	flags.StringVar(&o.krbConfig, "krb-config", "/etc/krb5.conf", "Kerberos configuration file")
	flags.StringVar(&o.ccache, "ccache", "", "Kerberos FILE credential cache instead of a password")
	flags.StringVar(&o.passwordFile, "password-file", "", "password file (otherwise use WINRM_PASSWORD)")
	flags.StringVar(&o.caFile, "ca", "", "PEM CA certificate for HTTPS")
	flags.StringVar(&o.shell, "shell", "cmd", "persistent shell: cmd or powershell")
	flags.StringVar(&o.command, "command", "", "run one command instead of an interactive shell")
	flags.IntVar(&o.port, "port", 0, "WinRM port (default 5985, or 5986 with -https)")
	flags.BoolVar(&o.https, "https", false, "use certificate-verified HTTPS")
	flags.DurationVar(&o.timeout, "timeout", 90*time.Second, "timeout per HTTP request (not total session duration)")
	if err := flags.Parse(args); err != nil {
		return o, err
	}
	if flags.NArg() != 0 {
		return o, errors.New("unexpected positional arguments; use -host and -user")
	}
	if strings.TrimSpace(o.host) == "" || strings.ContainsAny(o.host, "/\\ \t\r\n") {
		return o, errors.New("-host must be a hostname or IP address")
	}
	if o.auth != "kerberos" && o.auth != "basic" {
		return o, errors.New("-auth must be kerberos or basic")
	}
	if o.auth == "basic" && !o.https {
		return o, errors.New("basic authentication requires -https to protect credentials")
	}
	if o.auth == "basic" && o.ccache != "" {
		return o, errors.New("-ccache requires Kerberos authentication")
	}
	if o.ccache != "" && o.passwordFile != "" {
		return o, errors.New("choose either -ccache or -password-file")
	}
	if o.ccache == "" && o.user == "" {
		return o, errors.New("-user is required unless using -ccache")
	}
	if o.shell != "cmd" && o.shell != "powershell" {
		return o, errors.New("-shell must be cmd or powershell")
	}
	if o.port == 0 {
		o.port = 5985
		if o.https {
			o.port = 5986
		}
	}
	if o.port < 1 || o.port > 65535 || o.timeout <= 0 {
		return o, errors.New("-port must be 1..65535 and -timeout must be positive")
	}
	return o, nil
}

func newClient(o options) (*winrm.Client, error) {
	var password string
	if o.ccache == "" {
		password = os.Getenv("WINRM_PASSWORD")
		if o.passwordFile != "" {
			data, err := os.ReadFile(o.passwordFile)
			if err != nil {
				return nil, fmt.Errorf("read password file: %w", err)
			}
			password = strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
		}
		if password == "" {
			return nil, errors.New("provide -password-file or WINRM_PASSWORD, or use -ccache")
		}
	}
	var ca []byte
	if o.caFile != "" {
		var err error
		ca, err = os.ReadFile(o.caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA certificate: %w", err)
		}
	}
	endpoint := winrm.NewEndpoint(o.host, o.port, o.https, false, ca, nil, nil, o.timeout)
	params := *winrm.DefaultParameters
	if o.auth == "kerberos" {
		username, realm, found := strings.Cut(o.user, "@")
		if found {
			if username == "" || realm == "" || strings.Contains(realm, "@") {
				return nil, errors.New("invalid user@REALM principal")
			}
			if o.realm != "" && !strings.EqualFold(realm, o.realm) {
				return nil, errors.New("username realm does not match -realm")
			}
			o.realm = realm
		}
		cfg, err := config.Load(o.krbConfig)
		if err != nil {
			return nil, fmt.Errorf("load Kerberos configuration: %w", err)
		}
		if o.realm == "" {
			o.realm = cfg.LibDefaults.DefaultRealm
		}
		if o.realm == "" && o.ccache == "" {
			return nil, errors.New("provide -realm or configure default_realm in krb5.conf")
		}
		params.TransportDecorator = func() winrm.Transporter {
			return &winrm.ClientKerberos{
				Username: username, Password: password, Realm: o.realm,
				KrbConf: o.krbConfig, KrbCCache: o.ccache,
				MessageEncryption: winrm.KerberosEncryptionAuto,
			}
		}
	}
	return winrm.NewClientWithParameters(endpoint, o.user, password, &params)
}

func run(ctx context.Context, args []string, stdin io.ReadCloser, stdout, stderr io.Writer) (code int, resultErr error) {
	o, err := parseOptions(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0, nil
	}
	if err != nil {
		return 2, err
	}
	client, err := newClient(o)
	if err != nil {
		return 1, err
	}
	defer func() { resultErr = errors.Join(resultErr, client.Close()) }()
	shell, err := client.CreateShellWithContext(ctx)
	if err != nil {
		return 1, fmt.Errorf("connect to %s: %w", o.host, err)
	}
	defer func() { resultErr = errors.Join(resultErr, shell.Close()) }()
	command := o.command
	if command == "" {
		command = "cmd.exe /D /Q"
		if o.shell == "powershell" {
			command = "powershell.exe -NoLogo -NoProfile -Command -"
		}
	} else if o.shell == "powershell" {
		command = winrm.Powershell(command)
	}
	cmd, err := shell.ExecuteWithContext(ctx, command)
	if err != nil {
		return 1, fmt.Errorf("start remote command: %w", err)
	}
	code, err = streamCommand(ctx, cmd, stdin, stdout, stderr)
	return code, err
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	code, err := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "winrm:", err)
		if code == 0 {
			code = 1
		}
	}
	if ctx.Err() != nil {
		code = 130
	}
	if code < 0 || code > 255 {
		code = 1
	}
	os.Exit(code)
}
