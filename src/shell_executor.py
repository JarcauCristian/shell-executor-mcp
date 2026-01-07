from pathlib import Path

import fabric

from src.models import CommandResponse


class ShellExecutor:
    def __init__(self, hostname: str, user: str, key_file: Path) -> None:
        self._conn = fabric.Connection(
            hostname=hostname,
            user=user,
            connect_kwargs={
                "key_filename": key_file.as_posix(),
            },
        )

    def execute_command(self, command: str) -> CommandResponse:
        """Execute a single command onto the specified host."""
        response = self._conn.run(command)
        return CommandResponse(
            **{
                "stdout": response.stdout.strip(),
                "stderr": response.stderr.strip(),
                "exit_code": response.exited,
            }
        )
