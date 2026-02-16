from io import StringIO
from typing import Optional

import fabric
from paramiko import ECDSAKey, Ed25519Key, RSAKey
from paramiko.pkey import PKey

from src.models import CommandResponse
from src.vault_manager import VaultManager


class ShellExecutor:
    def __init__(self) -> None:
        self._vault_manager = VaultManager()
        self._conn: fabric.Connection | None = None
        self._username: str | None = None

    def set_connection_from_machine_id(self, hostname: str, machine_id: str) -> None:
        username, private_key = self._vault_manager.get_credentials(machine_id)
        pkey = self._load_private_key_from_string(private_key)

        self._conn = fabric.Connection(
            host=hostname,
            user=username,
            connect_kwargs={"pkey": pkey},
        )
        self._username = username

    def execute_command(self, command: str) -> CommandResponse:
        """Execute a single command onto the specified host."""
        if self._conn is None:
            return CommandResponse(stdout="", stderr="", exit_code=-1)

        response = self._conn.run(command)
        return CommandResponse(
            **{
                "stdout": response.stdout.strip(),
                "stderr": response.stderr.strip(),
                "exit_code": response.exited,
            }
        )

    def get_username(self) -> str:
        return self._username or ""

    @staticmethod
    def _load_private_key_from_string(key_data: str, passphrase: Optional[str] = None) -> PKey:
        """
        Load SSH private key from string data.
        Tries different key types automatically.
        """
        key_file = StringIO(key_data)

        # Try different key types in order of likelihood
        key_classes = [RSAKey, Ed25519Key, ECDSAKey]

        for key_class in key_classes:
            try:
                key_file.seek(0)
                return key_class.from_private_key(key_file, password=passphrase)
            except Exception:
                continue

        raise ValueError("Unable to load private key - unsupported format or invalid passphrase")
