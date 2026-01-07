import os

import hvac


class VaultManager:
    def __init__(self) -> None:
        """Initialize the Vault client with AppRole authentication."""
        self._role_id = os.getenv("VAULT_ROLE_ID")
        if not self._role_id:
            raise ValueError("Environment VAULT_ROLE_ID required, but is empty.")

        self._secret_id = os.getenv("VAULT_SECRET_ID")
        if not self._secret_id:
            raise ValueError("Environment VAULT_SECRET_ID required, but is empty.")

        self._base_url = os.getenv("VAULT_BASE_URL")
        if not self._base_url:
            raise ValueError("Environment VAULT_BASE_URL required, but is empty.")

        self._role_name = os.getenv("VAULT_ROLE_NAME")
        if not self._role_name:
            raise ValueError("Environment VAULT_ROLE_NAME required, but is empty.")

        self._client = hvac.Client(url=self._base_url, timeout=30)

        response = self._client.auth.approle.login(
            role_id=self._role_id,
            secret_id=self._secret_id,
        )

        self._client.token = response["auth"]["client_token"]

    def get_ssh_key(self) -> str:
        """Retrieve the SSH private key from Vault."""
        response = self._client.secrets.kv.v2.read_secret_version(
            path="app/config/ssh/ztp_key",
            mount_point=f"secrets-{self._role_name}",
        )

        data = response.get("data", {}).get("data")
        if not data:
            raise ValueError("There is no data field in response.")

        private_key = data.get("private_key")
        if not private_key:
            raise ValueError("There is no private_key field in data.")

        return private_key
