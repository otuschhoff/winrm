package winrm

import (
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/ChrisTrenkamp/goxpath"
	"github.com/ChrisTrenkamp/goxpath/tree"
	"github.com/ChrisTrenkamp/goxpath/tree/xmltree"
	"github.com/masterzen/winrm/soap"
)

type ExecuteCommandError struct {
	Inner error
	Body  string
}

func (e *ExecuteCommandError) Error() string {
	if e.Inner == nil {
		return "error"
	}

	return e.Inner.Error()
}

func (e *ExecuteCommandError) Is(err error) bool {
	_, ok := err.(*ExecuteCommandError)
	return ok
}

func (b *ExecuteCommandError) Unwrap() error {
	return b.Inner
}

func first(node tree.Node, xpath string) (string, error) {
	nodes, err := xPath(node, xpath)
	if err != nil {
		return "", err
	}
	if len(nodes) < 1 {
		return "", err
	}
	return nodes[0].ResValue(), nil
}

func any(node tree.Node, xpath string) (bool, error) {
	nodes, err := xPath(node, xpath)
	if err != nil {
		return false, err
	}
	if len(nodes) > 0 {
		return true, nil
	}
	return false, nil
}

func xPath(node tree.Node, xpath string) (tree.NodeSet, error) {
	xpExec := goxpath.MustParse(xpath)
	nodes, err := xpExec.ExecNode(node, soap.GetAllXPathNamespaces())
	if err != nil {
		return nil, err
	}
	return nodes, nil
}

func newExecuteCommandError(response string, format string, args ...interface{}) *ExecuteCommandError {
	return &ExecuteCommandError{fmt.Errorf(format, args...), response}
}

func parseResponse(response, expectedAction, idXPath string) (string, error) {
	doc, err := xmltree.ParseXML(strings.NewReader(response))
	if err != nil {
		return "", newExecuteCommandError(response, "parsing xml response: %w", err)
	}

	action, err := first(doc, "//a:Action")
	if err != nil {
		return "", newExecuteCommandError(response, "getting response action: %w", err)
	}

	if action == "http://schemas.dmtf.org/wbem/wsman/1/wsman/fault" {
		return "", newExecuteCommandError(response, "received error response")
	}
	if action == expectedAction {
		id, err := first(doc, idXPath)
		if err != nil {
			return "", newExecuteCommandError(response, "finding %v: %w", idXPath, err)
		}
		return id, nil
	}
	return "", newExecuteCommandError(response, "unsupported action: %v", action)
}

func ParseOpenShellResponse(response string) (string, error) {
	return parseResponse(
		response,
		"http://schemas.xmlsoap.org/ws/2004/09/transfer/CreateResponse",
		"//rsp:ShellId",
	)
}

func ParseExecuteCommandResponse(response string) (string, error) {
	return parseResponse(
		response,
		"http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandResponse",
		"//rsp:CommandId",
	)
}

// ParseSlurpOutputErrResponse ParseSlurpOutputErrResponse
func ParseSlurpOutputErrResponse(response string, stdout, stderr io.Writer) (bool, int, error) {
	var (
		finished bool
		exitCode int
	)

	doc, err := xmltree.ParseXML(strings.NewReader(response))
	if err != nil {
		return false, 0, err
	}

	stdouts, _ := xPath(doc, "//rsp:Stream[@Name='stdout']")
	for _, node := range stdouts {
		if err := writeOutputStream(stdout, "stdout", node.ResValue()); err != nil {
			return false, 0, err
		}
	}
	stderrs, _ := xPath(doc, "//rsp:Stream[@Name='stderr']")
	for _, node := range stderrs {
		if err := writeOutputStream(stderr, "stderr", node.ResValue()); err != nil {
			return false, 0, err
		}
	}

	ended, _ := any(doc, "//*[@State='http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done']")

	if ended {
		finished = ended
		if exitBool, _ := any(doc, "//rsp:ExitCode"); exitBool {
			exit, _ := first(doc, "//rsp:ExitCode")
			exitCode, err = strconv.Atoi(exit)
			if err != nil {
				return false, 0, fmt.Errorf("parse command exit code %q: %w", exit, err)
			}
		}
	} else {
		finished = false
	}

	return finished, exitCode, err
}

// ParseSlurpOutputResponse ParseSlurpOutputResponse
func ParseSlurpOutputResponse(response string, stream io.Writer, streamType string) (bool, int, error) {
	var (
		finished bool
		exitCode int
	)

	doc, err := xmltree.ParseXML(strings.NewReader(response))

	nodes, _ := xPath(doc, fmt.Sprintf("//rsp:Stream[@Name='%s']", streamType))
	for _, node := range nodes {
		if err := writeOutputStream(stream, streamType, node.ResValue()); err != nil {
			return false, 0, err
		}
	}

	ended, _ := any(doc, "//*[@State='http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done']")

	if ended {
		finished = ended
		if exitBool, _ := any(doc, "//rsp:ExitCode"); exitBool {
			exit, _ := first(doc, "//rsp:ExitCode")
			exitCode, err = strconv.Atoi(exit)
			if err != nil {
				return false, 0, fmt.Errorf("parse command exit code %q: %w", exit, err)
			}
		}
	} else {
		finished = false
	}

	return finished, exitCode, err
}

func writeOutputStream(writer io.Writer, stream, encoded string) error {
	content, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("decode %s stream: %w", stream, err)
	}
	written, err := writer.Write(content)
	if err != nil {
		return fmt.Errorf("write %s stream: %w", stream, err)
	}
	if written != len(content) {
		return fmt.Errorf("write %s stream: %w", stream, io.ErrShortWrite)
	}
	return nil
}
