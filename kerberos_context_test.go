package winrm

import "testing"

func TestClientKerberosResolveSPNUsesExplicitValue(t *testing.T) {
	k := &ClientKerberos{SPN: "HTTP/custom.example.com"}
	if got := k.resolveSPN(); got != "HTTP/custom.example.com" {
		t.Fatalf("resolveSPN() = %q, want %q", got, "HTTP/custom.example.com")
	}
}

func TestClientKerberosResolveSPNBuildsDefaultFromHostname(t *testing.T) {
	k := &ClientKerberos{Hostname: "Srv-Win.EXAMPLE.com."}
	if got := k.resolveSPN(); got != "HTTP/srv-win.example.com" {
		t.Fatalf("resolveSPN() = %q, want %q", got, "HTTP/srv-win.example.com")
	}
}

func TestClientKerberosResolveSPNBuildsDefaultFromHostPort(t *testing.T) {
	k := &ClientKerberos{Hostname: "srv-win.example.com:5985"}
	if got := k.resolveSPN(); got != "HTTP/srv-win.example.com" {
		t.Fatalf("resolveSPN() = %q, want %q", got, "HTTP/srv-win.example.com")
	}
}

func TestClientKerberosResolveSPNEmptyWithoutHost(t *testing.T) {
	k := &ClientKerberos{}
	if got := k.resolveSPN(); got != "" {
		t.Fatalf("resolveSPN() = %q, want empty string", got)
	}
}

func TestClientKerberosGetOrCreateContextReusesExisting(t *testing.T) {
	existing := &kerberosContext{spn: "HTTP/already.set"}
	k := &ClientKerberos{context: existing}

	got, err := k.getOrCreateContext()
	if err != nil {
		t.Fatalf("getOrCreateContext() unexpected error: %v", err)
	}
	if got != existing {
		t.Fatalf("getOrCreateContext() did not reuse existing context")
	}
}
