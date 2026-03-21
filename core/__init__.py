"""LinnyTool Core - Linux Security Hardening, Auditing & Grading."""

import subprocess
import logging
from typing import Optional

__version__ = "1.0.0"

logger = logging.getLogger("linnytool")


def run_command(
    cmd: list[str],
    timeout: int = 120,
    check: bool = False,
    input_data: Optional[str] = None,
) -> subprocess.CompletedProcess:
    """Standard subprocess wrapper used by all modules.

    Args:
        cmd: Command and arguments as list.
        timeout: Timeout in seconds (default 120).
        check: Raise CalledProcessError on non-zero exit.
        input_data: Optional stdin input string.

    Returns:
        CompletedProcess with stdout, stderr, returncode.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_data,
        )
        if check and result.returncode != 0:
            logger.error(
                "Command failed: %s (exit %d): %s",
                " ".join(cmd),
                result.returncode,
                result.stderr.strip(),
            )
            raise subprocess.CalledProcessError(
                result.returncode, cmd, result.stdout, result.stderr
            )
        return result
    except subprocess.TimeoutExpired:
        logger.error("Command timed out after %ds: %s", timeout, " ".join(cmd))
        raise
    except FileNotFoundError:
        logger.error("Command not found: %s", cmd[0])
        raise
