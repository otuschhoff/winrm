package winrm

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	. "gopkg.in/check.v1"
)

type shortOutputWriter struct{}

func (shortOutputWriter) Write(value []byte) (int, error) { return max(0, len(value)-1), nil }

func (s *WinRMSuite) TestOpenShellResponse(c *C) {
	response := createShellResponse
	shellID, err := ParseOpenShellResponse(response)
	if err != nil {
		c.Fatalf("response didn't parse: %s", err)
	}

	c.Assert("67A74734-DD32-4F10-89DE-49A060483810", Equals, shellID)
}

func (s *WinRMSuite) TestOpenShellResponseError(c *C) {
	response := createShellResponseWithError
	shellId, err := ParseOpenShellResponse(response)
	if err == nil {
		c.Fatal("expected error")
	}
	c.Assert(shellId, Equals, "")

	var execCmdRespErr *ExecuteCommandError
	if !errors.As(err, &execCmdRespErr) {
		c.Fatal("expected err to be of type ExecuteCommandError")
	}
}

func (s *WinRMSuite) TestExecuteCommandResponse(c *C) {
	response := executeCommandResponse

	commandID, err := ParseExecuteCommandResponse(response)
	if err != nil {
		c.Fatalf("response didn't parse: %s", err)
	}

	c.Assert("1A6DEE6B-EC68-4DD6-87E9-030C0048ECC4", Equals, commandID)
}

func (s *WinRMSuite) TestExecuteCommandResponseError(c *C) {
	response := executeCommandResponseWithError

	commandID, err := ParseExecuteCommandResponse(response)
	if err == nil {
		c.Fatal("expected error")
	}
	c.Assert(commandID, Equals, "")

	var execCmdRespErr *ExecuteCommandError
	if !errors.As(err, &execCmdRespErr) {
		c.Fatal("expected err to be of type ExecuteCommandError")
	}
}

func (s *WinRMSuite) TestSlurpOutputResponse(c *C) {
	response := outputResponse

	var stdout, stderr bytes.Buffer
	finished, _, err := ParseSlurpOutputErrResponse(response, &stdout, &stderr)
	if err != nil {
		c.Fatalf("response didn't parse: %s", err)
	}

	c.Assert(finished, Equals, false)
	c.Assert("That's all folks!!!", Equals, stdout.String())
	c.Assert("This is stderr, I'm pretty sure!", Equals, stderr.String())
}

func (s *WinRMSuite) TestSlurpOutputSingleResponse(c *C) {
	response := singleOutputResponse

	var stream bytes.Buffer
	finished, _, err := ParseSlurpOutputResponse(response, &stream, "stdout")
	if err != nil {
		c.Fatalf("response didn't parse: %s", err)
	}

	c.Assert(finished, Equals, false)
	c.Assert("That's all folks!!!", Equals, stream.String())
}

func (s *WinRMSuite) TestDoneSlurpOutputResponse(c *C) {
	response := doneCommandResponse

	var stdout, stderr bytes.Buffer
	finished, code, err := ParseSlurpOutputErrResponse(response, &stdout, &stderr)
	if err != nil {
		c.Fatalf("response didn't parse: %s", err)
	}

	c.Assert(finished, Equals, true)
	c.Assert(code, Equals, 123)
	c.Assert("", Equals, stdout.String())
	c.Assert("", Equals, stderr.String())
}

func (s *WinRMSuite) TestSlurpOutputRejectsMalformedData(c *C) {
	invalidBase64 := strings.Replace(outputResponse, "VGhhdCdzIGFsbCBmb2xrcyEhIQ==", "%%%", 1)
	_, _, err := ParseSlurpOutputErrResponse(invalidBase64, io.Discard, io.Discard)
	c.Assert(err, ErrorMatches, ".*decode stdout stream.*")

	_, _, err = ParseSlurpOutputErrResponse(outputResponse, shortOutputWriter{}, io.Discard)
	c.Assert(errors.Is(err, io.ErrShortWrite), Equals, true)

	invalidExit := strings.Replace(doneCommandResponse, "<rsp:ExitCode>123</rsp:ExitCode>", "<rsp:ExitCode>invalid</rsp:ExitCode>", 1)
	_, _, err = ParseSlurpOutputErrResponse(invalidExit, io.Discard, io.Discard)
	c.Assert(err, ErrorMatches, ".*parse command exit code.*")
}

func (s *WinRMSuite) TestSlurpSingleOutputRejectsMalformedXML(c *C) {
	_, _, err := ParseSlurpOutputResponse("<not-closed", io.Discard, "stdout")
	c.Assert(err, NotNil)
}

func (s *WinRMSuite) TestResponseSemantics(c *C) {
	emptyShellID := strings.Replace(createShellResponse,
		"<rsp:ShellId>67A74734-DD32-4F10-89DE-49A060483810</rsp:ShellId>",
		"<rsp:ShellId></rsp:ShellId>", 1)
	_, err := ParseOpenShellResponse(emptyShellID)
	c.Assert(err, ErrorMatches, ".*missing.*ShellId.*")

	emptyCommandID := strings.Replace(executeCommandResponse,
		"<rsp:CommandId>1A6DEE6B-EC68-4DD6-87E9-030C0048ECC4</rsp:CommandId>",
		"<rsp:CommandId></rsp:CommandId>", 1)
	_, err = ParseExecuteCommandResponse(emptyCommandID)
	c.Assert(err, ErrorMatches, ".*missing.*CommandId.*")

	missingExit := strings.Replace(doneCommandResponse,
		"<rsp:ExitCode>123</rsp:ExitCode>", "", 1)
	_, _, err = ParseSlurpOutputErrResponse(missingExit, io.Discard, io.Discard)
	c.Assert(err, ErrorMatches, ".*missing.*ExitCode.*")

	wrongAction := strings.Replace(outputResponse, "shell/ReceiveResponse", "shell/CommandResponse", 1)
	_, _, err = ParseSlurpOutputErrResponse(wrongAction, io.Discard, io.Discard)
	c.Assert(err, ErrorMatches, ".*unsupported action.*")
}

func (s *WinRMSuite) TestOutputResponseFaultClassification(c *C) {
	_, _, err := ParseSlurpOutputErrResponse(operationTimeoutResponse, io.Discard, io.Discard)
	c.Assert(err, NotNil)
	var fault *SOAPFaultError
	c.Assert(errors.As(err, &fault), Equals, true)
	c.Assert(errors.Is(err, ErrOperationTimeout), Equals, true)
	c.Assert(fault.WSManCode, Equals, "2150858793")

	_, _, err = ParseSlurpOutputErrResponse(executeCommandResponseWithError, io.Discard, io.Discard)
	c.Assert(err, NotNil)
	c.Assert(errors.Is(err, ErrOperationTimeout), Equals, false)
}

func (s *WinRMSuite) TestOutputResponseValidatesCommandIdentityAndStream(c *C) {
	_, _, err := parseSlurpOutputErrResponse(outputResponse, io.Discard, io.Discard, "OTHER-COMMAND")
	c.Assert(err, ErrorMatches, ".*unexpected command ID.*")

	_, _, err = ParseSlurpOutputResponse(outputResponse, io.Discard, "stdout' or @Name='stderr")
	c.Assert(err, ErrorMatches, ".*unsupported stream.*")
}

func FuzzParseCommandResponses(f *testing.F) {
	f.Add(createShellResponse)
	f.Add(executeCommandResponseWithError)
	f.Add("<not-closed")
	f.Fuzz(func(t *testing.T, response string) {
		if len(response) > 1<<20 {
			t.Skip()
		}
		_, _ = ParseOpenShellResponse(response)
		_, _ = ParseExecuteCommandResponse(response)
	})
}

func FuzzParseOutputResponses(f *testing.F) {
	f.Add(outputResponse, "stdout")
	f.Add(doneCommandResponse, "stderr")
	f.Add(operationTimeoutResponse, "stdout")
	f.Add(strings.Replace(doneCommandResponse, "<rsp:ExitCode>123</rsp:ExitCode>", "", 1), "stderr")
	f.Add("<not-closed", "stdout")
	f.Add(outputResponse, "stdout' or @Name='stderr")
	f.Fuzz(func(t *testing.T, response, stream string) {
		if len(response) > 1<<20 || len(stream) > 32 {
			t.Skip()
		}
		_, _, _ = ParseSlurpOutputErrResponse(response, io.Discard, io.Discard)
		_, _, _ = ParseSlurpOutputResponse(response, io.Discard, stream)
	})
}

func BenchmarkParseOutputResponse(b *testing.B) {
	for _, size := range []int{1 << 10, 64 << 10} {
		b.Run(fmt.Sprintf("decoded-%d", size), func(b *testing.B) {
			response := kerberosPhase4Receive(bytes.Repeat([]byte("x"), size), nil, true, 0)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, _, err := ParseSlurpOutputErrResponse(response, io.Discard, io.Discard); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
