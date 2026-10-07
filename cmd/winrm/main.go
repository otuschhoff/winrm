package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strconv"
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
	var requestTTY, disableTTY bool
	flags := flag.NewFlagSet("winrm", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: winrm [options] [user@]host [command [argument ...]]")
		fmt.Fprintln(stderr, "       winrm [options] -host host [-command command]")
		fmt.Fprintln(stderr, "\nOptions must precede the destination. WinRM does not provide a PTY or port forwarding.")
		flags.PrintDefaults()
	}
	flags.StringVar(&o.host, "host", "", "destination hostname (legacy alternative to [user@]host)")
	flags.StringVar(&o.user, "l", "", "login username (defaults to destination user or local username)")
	flags.StringVar(&o.user, "user", "", "alias for -l; accepts user@REALM")
	flags.IntVar(&o.port, "p", 0, "WinRM port (default 5985, or 5986 with -https)")
	flags.BoolVar(&disableTTY, "T", false, "disable pseudo-terminal allocation (WinRM always runs without a PTY)")
	flags.BoolVar(&requestTTY, "t", false, "request a pseudo-terminal (unsupported by WinRM)")
	flags.StringVar(&o.auth, "auth", "kerberos", "authentication: kerberos or basic (requires HTTPS)")
	flags.StringVar(&o.realm, "realm", "", "Kerberos realm (defaults to user realm or krb5.conf)")
	flags.StringVar(&o.krbConfig, "krb-config", "/etc/krb5.conf", "Kerberos configuration file")
	flags.StringVar(&o.ccache, "ccache", "", "Kerberos FILE credential cache instead of a password")
	flags.StringVar(&o.passwordFile, "password-file", "", "password file (otherwise use WINRM_PASSWORD or prompt)")
	flags.StringVar(&o.caFile, "ca", "", "PEM CA certificate for HTTPS")
	flags.StringVar(&o.shell, "shell", "powershell", "shell mode: powershell, ps (alias), or cmd")
	selectShell := func(enabledMode, disabledMode string) func(string) error {
		return func(value string) error {
			enabled, err := strconv.ParseBool(value)
			if err != nil {
				return err
			}
			o.shell = disabledMode
			if enabled {
				o.shell = enabledMode
			}
			return nil
		}
	}
	flags.BoolFunc("ps", "use PowerShell mode (default)", selectShell("powershell", "cmd"))
	flags.BoolFunc("cmd", "use legacy cmd.exe mode (shortcut for -shell cmd)", selectShell("cmd", "powershell"))
	flags.StringVar(&o.command, "command", "", "run one command instead of an interactive shell")
	flags.IntVar(&o.port, "port", 0, "alias for -p")
	flags.BoolVar(&o.https, "https", false, "use certificate-verified HTTPS")
	flags.DurationVar(&o.timeout, "timeout", 90*time.Second, "timeout per HTTP request (not total session duration)")
	if err := flags.Parse(normalizeSSHFlags(args, flags)); err != nil {
		return o, err
	}
	if requestTTY {
		return o, errors.New("-t is unsupported: WinRM does not provide a pseudo-terminal; use -T or omit -t")
	}
	if flags.NArg() > 0 {
		if o.host != "" {
			return o, errors.New("choose either a positional destination or -host, not both")
		}
		destination := flags.Arg(0)
		if at := strings.LastIndexByte(destination, '@'); at >= 0 {
			if at == 0 {
				return o, errors.New("destination username must not be empty")
			}
			if o.user == "" {
				o.user = destination[:at]
			}
			destination = destination[at+1:]
		}
		o.host = destination
		if flags.NArg() > 1 {
			if o.command != "" {
				return o, errors.New("choose either a positional command or -command, not both")
			}
			o.command = strings.Join(flags.Args()[1:], " ")
		}
	}
	if strings.HasPrefix(o.host, "[") || strings.HasSuffix(o.host, "]") {
		if !strings.HasPrefix(o.host, "[") || !strings.HasSuffix(o.host, "]") {
			return o, errors.New("bracketed destination must be an IPv6 address")
		}
		o.host = o.host[1 : len(o.host)-1]
		if net.ParseIP(o.host) == nil || !strings.Contains(o.host, ":") {
			return o, errors.New("bracketed destination must be an IPv6 address")
		}
	}
	if strings.TrimSpace(o.host) == "" || strings.ContainsAny(o.host, "/\\ \t\r\n") {
		return o, errors.New("destination must be a hostname or IP address")
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
		currentUser, err := user.Current()
		if err != nil {
			return o, fmt.Errorf("determine local username; specify -l: %w", err)
		}
		o.user = currentUser.Username
		if slash := strings.LastIndexByte(o.user, '\\'); slash >= 0 {
			o.user = o.user[slash+1:]
		}
		if o.user == "" {
			return o, errors.New("local username is empty; specify -l")
		}
	}
	if o.shell == "ps" {
		o.shell = "powershell"
	}
	if o.shell != "cmd" && o.shell != "powershell" {
		return o, errors.New("-shell must be cmd, powershell, or ps")
	}
	if o.port == 0 {
		o.port = 5985
		if o.https {
			o.port = 5986
		}
	}
	if o.port < 1 || o.port > 65535 || o.timeout <= 0 {
		return o, errors.New("-p/-port must be 1..65535 and -timeout must be positive")
	}
	return o, nil
}

func normalizeSSHFlags(args []string, flags *flag.FlagSet) []string {
	var normalized []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" || !strings.HasPrefix(arg, "-") || arg == "-" {
			return append(normalized, args[i:]...)
		}
		name, _, hasValue := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		if f := flags.Lookup(name); f != nil {
			normalized = append(normalized, arg)
			boolean, ok := f.Value.(interface{ IsBoolFlag() bool })
			if !hasValue && !(ok && boolean.IsBoolFlag()) && i+1 < len(args) {
				i++
				normalized = append(normalized, args[i])
			}
			continue
		}
		// Expand SSH-style attached arguments and groups, e.g. -p5985 or -Tp5985.
		if len(arg) > 2 && arg[1] != '-' {
			short := arg[1:]
			for len(short) > 0 && (short[0] == 'T' || short[0] == 't') {
				normalized = append(normalized, "-"+short[:1])
				short = short[1:]
			}
			if len(short) > 0 && (short[0] == 'l' || short[0] == 'p') {
				normalized = append(normalized, "-"+short[:1])
				if len(short) > 1 {
					normalized = append(normalized, short[1:])
				} else if i+1 < len(args) {
					i++
					normalized = append(normalized, args[i])
				}
				continue
			}
			if short == "" {
				continue
			}
			if short != arg[1:] {
				normalized = append(normalized, "-"+short)
				continue
			}
		}
		normalized = append(normalized, arg)
	}
	return normalized
}

func newClient(o options, prompt func() (string, error)) (*winrm.Client, error) {
	password, err := resolvePassword(o, prompt)
	if err != nil {
		return nil, err
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

func shellCommand(o options) string {
	if o.command == "" {
		if o.shell == "powershell" {
			return "powershell.exe -NoLogo -NoProfile -Command -"
		}
		return "cmd.exe /D /Q"
	}
	if o.shell == "powershell" {
		return winrm.Powershell(o.command)
	}
	return o.command
}

func run(ctx context.Context, args []string, stdin io.ReadCloser, stdout, stderr io.Writer) (code int, resultErr error) {
	o, err := parseOptions(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0, nil
	}
	if err != nil {
		return 2, err
	}
	client, err := newClient(o, func() (string, error) {
		return promptPassword(ctx, stdin, stderr)
	})
	if err != nil {
		return 1, err
	}
	defer func() { resultErr = errors.Join(resultErr, client.Close()) }()
	shell, err := client.CreateShellWithContext(ctx)
	if err != nil {
		return 1, fmt.Errorf("connect to %s: %w", o.host, err)
	}
	defer func() { resultErr = errors.Join(resultErr, shell.Close()) }()
	cmd, err := shell.ExecuteWithContext(ctx, shellCommand(o))
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
