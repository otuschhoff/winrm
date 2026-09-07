import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from compare_pywinrm import trim_terminal_line_ending, validate_hostname_result


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
        self.assertEqual(validate_hostname_result("WIN-HOST", "", 0, "win-host"), "")

    def test_rejects_wrong_hostname(self):
        self.assertIn("stdout", validate_hostname_result("other", "", 0, "win-host"))

    def test_rejects_stderr(self):
        self.assertIn("stderr", validate_hostname_result("win-host", "warning", 0, "win-host"))

    def test_rejects_nonzero_exit(self):
        self.assertIn("code 1", validate_hostname_result("win-host", "", 1, "win-host"))


if __name__ == "__main__":
    unittest.main()