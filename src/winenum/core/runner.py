import subprocess
import re

def run_command(cmd: list, timeout: int = 15) -> tuple[int, str, str]:
    """Run a command and return exit code, stdout, stderr"""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        # Strip ANSI escape sequences so regex and string matching doesn't fail on colored tools (like netexec)
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        clean_stdout = ansi_escape.sub('', result.stdout)
        clean_stderr = ansi_escape.sub('', result.stderr)
        
        return result.returncode, clean_stdout, clean_stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except FileNotFoundError:
        return -2, "", f"Command not found: {cmd[0]}"
    except Exception as e:
        return -3, "", str(e)
