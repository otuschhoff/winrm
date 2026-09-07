import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from compare_pywinrm import run_scenarios, trim_terminal_line_ending, validate_hostname_result


class FakeProtocol:
    def __init__(self):
        self.calls = []
        self.transport = self

    def open_shell(self):
        shell_id = f"shell-{len(self.calls)}"
        self.calls.append(("open", shell_id))
        return shell_id

    def run_command(self, shell_id, command):
        self.calls.append(("run", shell_id, command))
        return f"command-{shell_id}"

    def send_command_input(self, shell_id, command_id, data, end=False):
        self.calls.append(("stdin", shell_id, command_id, data, end))

    def get_command_output(self, shell_id, command_id):
        self.calls.append(("output", shell_id, command_id))
        return b"stdout", b"stderr", 23

    def cleanup_command(self, shell_id, command_id):
        self.calls.append(("cleanup", shell_id, command_id))

    def close_shell(self, shell_id, close_session=True):
        self.calls.append(("close-shell", shell_id, close_session))

    def close_session(self):
        self.calls.append(("close-session",))


class RunScenariosTests(unittest.TestCase):
    def test_reuses_protocol_and_closes_each_command(self):
        protocol = FakeProtocol()
        session = type("Session", (), {"protocol": protocol})()

        results = run_scenarios(
            session,
            [
                {"name": "plain", "command": "hostname"},
                {"name": "stdin", "command": "more", "stdin": "input", "send_stdin": True},
            ],
        )

        self.assertEqual(
            results,
            [
                {"name": "plain", "stdout": "stdout", "stderr": "stderr", "exit_code": 23},
                {"name": "stdin", "stdout": "stdout", "stderr": "stderr", "exit_code": 23},
            ],
        )
        self.assertIn(("stdin", "shell-5", "command-shell-5", b"input", True), protocol.calls)
        self.assertEqual([call for call in protocol.calls if call[0] == "close-shell"], [("close-shell", "shell-0", False), ("close-shell", "shell-5", False)])
        self.assertEqual(protocol.calls[-1], ("close-session",))


class TrimTerminalLineEndingTests(unittest.TestCase):
    def test_removes_lf(self):
        self.assertEqual(trim_terminal_line_ending(" secret \n"), " secret ")

    def test_removes_crlf(self):
        self.assertEqual(trim_terminal_line_ending(" secret \r\n"), " secret ")

    def test_preserves_value_without_ending(self):
        self.assertEqual(trim_terminal_line_ending(" secret "), " secret ")

    def test_removes_only_one_ending(self):
        self.assertEqual(trim_terminal_line_ending("secret\n\n"), "secret\n")

    def test_empty_value_remains_empty(self):
        self.assertEqual(trim_terminal_line_ending(""), "")


class ValidateHostnameResultTests(unittest.TestCase):
    def test_accepts_expected_result(self):
        self.assertEqual(validate_hostname_result("SERVER", "", 0, "server"), "")

    def test_rejects_wrong_hostname(self):
        self.assertIn("stdout", validate_hostname_result("other", "", 0, "server"))

    def test_rejects_stderr(self):
        self.assertIn("stderr", validate_hostname_result("server", "warning", 0, "server"))

    def test_rejects_nonzero_exit(self):
        self.assertIn("code 1", validate_hostname_result("server", "", 1, "server"))


if __name__ == "__main__":
    unittest.main()