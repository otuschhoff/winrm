package winrm

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/ChrisTrenkamp/goxpath"
	"github.com/ChrisTrenkamp/goxpath/tree"
	"github.com/ChrisTrenkamp/goxpath/tree/xmltree"
	"github.com/otuschhoff/winrm/soap"
)

const (
	faultAction           = "http://schemas.dmtf.org/wbem/wsman/1/wsman/fault"
	receiveResponseAction = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/ReceiveResponse"
	operationTimeoutCode  = "2150858793"
)

var ErrOperationTimeout = errors.New("WS-Management operation timeout")

// SOAPFaultError describes a SOAP/WS-Management fault without retaining the
// complete response, which may contain sensitive endpoint data.
type SOAPFaultError struct {
	Code      string
	Subcode   string
	Reason    string
	WSManCode string
}

func (e *SOAPFaultError) Error() string {
	detail := e.Reason
	if detail == "" {
		detail = e.Subcode
	}
	if detail == "" {
		detail = e.Code
	}
	if detail == "" {
		detail = "unknown fault"
	}
	if e.WSManCode != "" {
		return fmt.Sprintf("WS-Management fault %s: %s", e.WSManCode, detail)
	}
	return "WS-Management fault: " + detail
}

func (e *SOAPFaultError) Is(target error) bool {
	return target == ErrOperationTimeout && e.WSManCode == operationTimeoutCode
}

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

func (b *ExecuteCommandError) Unwrap() error {
	return b.Inner
}

func first(node tree.Node, xpath string) (string, error) {
	nodes, err := xPath(node, xpath)
	if err != nil {
		return "", err
	}
	if len(nodes) < 1 {
		return "", fmt.Errorf("missing required element %s", xpath)
	}
	return nodes[0].ResValue(), nil
}

func optionalFirst(node tree.Node, xpath string) string {
	nodes, err := xPath(node, xpath)
	if err != nil || len(nodes) == 0 {
		return ""
	}
	return strings.TrimSpace(nodes[0].ResValue())
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

func parseSOAPFault(doc tree.Node) *SOAPFaultError {
	return &SOAPFaultError{
		Code:      optionalFirst(doc, "//s:Fault/s:Code/s:Value"),
		Subcode:   optionalFirst(doc, "//s:Fault/s:Code/s:Subcode/s:Value"),
		Reason:    optionalFirst(doc, "//s:Fault/s:Reason/s:Text"),
		WSManCode: optionalFirst(doc, "//f:WSManFault/@Code"),
	}
}

func parseSOAPFaultResponse(response string) (*SOAPFaultError, error) {
	doc, err := xmltree.ParseXML(strings.NewReader(response))
	if err != nil {
		return nil, fmt.Errorf("parse SOAP fault: %w", err)
	}
	action, err := responseAction(doc)
	if err != nil {
		return nil, fmt.Errorf("parse SOAP fault action: %w", err)
	}
	if action != faultAction {
		return nil, fmt.Errorf("response action %q is not a SOAP fault", action)
	}
	return parseSOAPFault(doc), nil
}

func responseAction(doc tree.Node) (string, error) {
	action, err := first(doc, "//a:Action")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(action), nil
}

func parseResponse(response, expectedAction, idXPath string) (string, error) {
	doc, err := xmltree.ParseXML(strings.NewReader(response))
	if err != nil {
		return "", newExecuteCommandError(response, "parsing xml response: %w", err)
	}

	action, err := responseAction(doc)
	if err != nil {
		return "", newExecuteCommandError(response, "getting response action: %w", err)
	}

	if action == faultAction {
		return "", &ExecuteCommandError{Inner: parseSOAPFault(doc), Body: response}
	}
	if action == expectedAction {
		id, err := first(doc, idXPath)
		if err != nil {
			return "", newExecuteCommandError(response, "finding %v: %w", idXPath, err)
		}
		id = strings.TrimSpace(id)
		if id == "" {
			return "", newExecuteCommandError(response, "missing required %s", strings.TrimPrefix(idXPath, "//rsp:"))
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
	return parseSlurpOutputErrResponse(response, stdout, stderr, "")
}

func parseSlurpOutputErrResponse(response string, stdout, stderr io.Writer, expectedCommandID string) (bool, int, error) {
	doc, err := xmltree.ParseXML(strings.NewReader(response))
	if err != nil {
		return false, 0, err
	}
	if err := validateOutputEnvelope(doc, expectedCommandID); err != nil {
		return false, 0, err
	}

	stdouts, err := xPath(doc, "//rsp:Stream[@Name='stdout']")
	if err != nil {
		return false, 0, err
	}
	for _, node := range stdouts {
		if err := writeOutputStream(stdout, "stdout", node.ResValue()); err != nil {
			return false, 0, err
		}
	}
	stderrs, err := xPath(doc, "//rsp:Stream[@Name='stderr']")
	if err != nil {
		return false, 0, err
	}
	for _, node := range stderrs {
		if err := writeOutputStream(stderr, "stderr", node.ResValue()); err != nil {
			return false, 0, err
		}
	}

	return outputCompletion(doc)
}

// ParseSlurpOutputResponse ParseSlurpOutputResponse
func ParseSlurpOutputResponse(response string, stream io.Writer, streamType string) (bool, int, error) {
	doc, err := xmltree.ParseXML(strings.NewReader(response))
	if err != nil {
		return false, 0, err
	}
	if err := validateOutputEnvelope(doc, ""); err != nil {
		return false, 0, err
	}

	streamXPath := ""
	switch streamType {
	case "stdout":
		streamXPath = "//rsp:Stream[@Name='stdout']"
	case "stderr":
		streamXPath = "//rsp:Stream[@Name='stderr']"
	default:
		return false, 0, fmt.Errorf("unsupported stream %q", streamType)
	}
	nodes, err := xPath(doc, streamXPath)
	if err != nil {
		return false, 0, err
	}
	for _, node := range nodes {
		if err := writeOutputStream(stream, streamType, node.ResValue()); err != nil {
			return false, 0, err
		}
	}
	return outputCompletion(doc)
}

func validateOutputEnvelope(doc tree.Node, expectedCommandID string) error {
	action, err := responseAction(doc)
	if err != nil {
		return fmt.Errorf("getting response action: %w", err)
	}
	if action == faultAction {
		return parseSOAPFault(doc)
	}
	if action != receiveResponseAction {
		return fmt.Errorf("unsupported action: %s", action)
	}
	if expectedCommandID == "" {
		return nil
	}
	nodes, err := xPath(doc, "//rsp:Stream/@CommandId | //rsp:CommandState/@CommandId")
	if err != nil {
		return err
	}
	if len(nodes) == 0 {
		return errors.New("missing command ID in output response")
	}
	for _, node := range nodes {
		if actual := strings.TrimSpace(node.ResValue()); actual != expectedCommandID {
			return fmt.Errorf("unexpected command ID %q, expected %q", actual, expectedCommandID)
		}
	}
	return nil
}

func outputCompletion(doc tree.Node) (bool, int, error) {
	ended, err := any(doc, "//rsp:CommandState[@State='http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done']")
	if err != nil {
		return false, 0, err
	}
	if !ended {
		return false, 0, nil
	}
	exit, err := first(doc, "//rsp:CommandState/rsp:ExitCode")
	if err != nil {
		return false, 0, fmt.Errorf("missing required ExitCode: %w", err)
	}
	exitCode, err := strconv.Atoi(strings.TrimSpace(exit))
	if err != nil {
		return false, 0, fmt.Errorf("parse command exit code %q: %w", exit, err)
	}
	return true, exitCode, nil
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
