package main

import (
	"context"
	"fmt"
	"net"
	"strings"
)

func targetIdentity(o options) string {
	if o.identityHost != "" {
		return o.identityHost
	}
	return o.host
}

func resolveTarget(ctx context.Context, o options, lookupAddr func(context.Context, string) ([]string, error)) (options, error) {
	if net.ParseIP(o.host) == nil {
		return o, nil
	}
	lookupContext, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	names, err := lookupAddr(lookupContext, o.host)
	hint := "Could not determine a hostname for IP " + o.host + ". Configure a reverse-DNS PTR record or connect using the server's hostname."
	if err != nil {
		return o, withOperation("resolve target hostname", hint, err)
	}
	for _, name := range names {
		name = strings.TrimSuffix(name, ".")
		if validTargetHostname(name) {
			o.identityHost = name
			return o, nil
		}
	}
	return o, withOperation("resolve target hostname", hint, fmt.Errorf("reverse lookup for %s returned no usable hostname", o.host))
}

func validTargetHostname(name string) bool {
	if name == "" || len(name) > 253 || net.ParseIP(name) != nil {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-') {
				return false
			}
		}
	}
	return true
}
