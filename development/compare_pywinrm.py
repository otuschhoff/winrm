#!/usr/bin/env python3

import json
import os
import subprocess
import sys
import tempfile


def trim_terminal_line_ending(value):
    if value.endswith("\r\n"):
        return value[:-2]
    if value.endswith("\n"):
        return value[:-1]
    return value


def validate_hostname_result(stdout, stderr, exit_code, expected_hostname):
    if exit_code != 0:
        return f"hostname exited with code {exit_code}"
    if stdout.casefold() != expected_hostname.casefold():
        return "hostname stdout did not match the expected result"
    if stderr:
        return "hostname stderr was not empty"
    return ""


def result(**values):
    output = {
        "client": "python",
        "success": False,
        "exit_code": -1,
        "stdout": "",
        "stderr": "",
        "http_status": 0,
        "error_kind": "",
        "error": "",
        "endpoint": "",
        "protection_mode": "kerberos-message-encryption-auto",
        "runtime_version": sys.version.split()[0],
        "client_version": "unknown",
        "outcome": "failure",
        "results": [],
    }
    output.update(values)
    return output


def run_scenarios(session, scenarios):
    results = []
    protocol = session.protocol
    try:
        for scenario in scenarios:
            shell_id = protocol.open_shell()
            try:
                command_id = protocol.run_command(shell_id, scenario["command"])
                try:
                    if scenario.get("send_stdin", False):
                        protocol.send_command_input(
                            shell_id,
                            command_id,
                            scenario.get("stdin", "").encode("utf-8"),
                            end=True,
                        )
                    stdout, stderr, exit_code = protocol.get_command_output(shell_id, command_id)
                finally:
                    protocol.cleanup_command(shell_id, command_id)
            finally:
                protocol.close_shell(shell_id, close_session=False)
            results.append(
                {
                    "name": scenario["name"],
                    "stdout": stdout.decode("utf-8"),
                    "stderr": stderr.decode("utf-8"),
                    "exit_code": exit_code,
                }
            )
    finally:
        protocol.transport.close_session()
    return results


def main():
    try:
        import winrm
        from winrm.exceptions import InvalidCredentialsError, WinRMTransportError
    except ImportError as error:
        return result(error_kind="setup", error=f"import pywinrm: {error}")

    client_version = getattr(winrm, "__version__", "unknown")

    try:
        host = os.environ["WINRM_HOST"]
        principal = os.environ["WINRM_KRB_PRINCIPAL"]
        auth_mode = os.environ["WINRM_KRB_AUTH"]
    except KeyError as error:
        return result(client_version=client_version, error_kind="setup", error=f"missing environment variable: {error.args[0]}")

    endpoint = f"http://{host}:5985/wsman"

    def safe_result(**values):
        error = str(values.get("error", ""))
        values["error"] = error.replace(principal, "<principal>")
        return result(client_version=client_version, endpoint=endpoint, **values)

    with tempfile.TemporaryDirectory(prefix="pywinrm-krb5-") as cache_dir:
        environment = os.environ.copy()
        environment["KRB5CCNAME"] = f"FILE:{cache_dir}/ccache"
        if auth_mode == "keytab":
            keytab_path = os.environ.get("WINRM_KRB_KEYTAB", "")
            if not keytab_path:
                return safe_result(error_kind="setup", error="WINRM_KRB_KEYTAB is required for keytab authentication")
            command = [
                "kinit",
                "-k",
                "-t",
                keytab_path,
                principal,
            ]
            password = None
        elif auth_mode == "password":
            command = ["kinit", principal]
            try:
                with open(os.environ["WINRM_KRB_PASSWORD_FILE"], encoding="utf-8", newline="") as password_file:
                    password = trim_terminal_line_ending(password_file.read())
                if not password:
                    return safe_result(error_kind="setup", error="password must not be empty")
                password += "\n"
            except (KeyError, OSError) as error:
                return safe_result(error_kind="setup", error=f"read password file: {error}")
        else:
            return safe_result(error_kind="setup", error=f"unsupported auth mode: {auth_mode}")

        try:
            ticket = subprocess.run(
                command,
                input=password,
                text=True,
                capture_output=True,
                env=environment,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            return safe_result(error_kind="kinit", error=f"run kinit: {error}")
        if ticket.returncode != 0:
            return safe_result(
                error_kind="kinit",
                error=f"kinit exited with {ticket.returncode}",
            )

        os.environ["KRB5CCNAME"] = environment["KRB5CCNAME"]
        if "KRB5_CONFIG" in environment:
            os.environ["KRB5_CONFIG"] = environment["KRB5_CONFIG"]
        try:
            session = winrm.Session(
                endpoint,
                auth=("", ""),
                transport="kerberos",
                message_encryption="auto",
                operation_timeout_sec=15,
                read_timeout_sec=20,
            )
            encoded_scenarios = os.environ.get("WINRM_KRB_SCENARIOS", "")
            if encoded_scenarios:
                results = run_scenarios(session, json.loads(encoded_scenarios))
                return safe_result(success=True, results=results, outcome="success")
            response = session.run_cmd("hostname")
            stdout = response.std_out.decode("utf-8", errors="replace").rstrip("\r\n")
            stderr = response.std_err.decode("utf-8", errors="replace").rstrip("\r\n")
            expected_hostname = os.environ.get("WINRM_EXPECTED_HOSTNAME", "")
            validation_error = validate_hostname_result(stdout, stderr, response.status_code, expected_hostname)
            success = not validation_error
            return safe_result(
                success=success,
                exit_code=response.status_code,
                stdout=stdout,
                stderr=stderr,
                error_kind="" if success else "validation",
                error=validation_error,
                outcome="success" if success else "failure",
            )
        except InvalidCredentialsError as error:
            return safe_result(http_status=401, error_kind="auth", error=str(error))
        except WinRMTransportError as error:
            return safe_result(
                http_status=getattr(error, "code", 0) or 0,
                error_kind="transport",
                error=str(error),
            )
        except Exception as error:
            return safe_result(error_kind="client", error=f"{type(error).__name__}: {error}")


if __name__ == "__main__":
    print(json.dumps(main(), sort_keys=True))