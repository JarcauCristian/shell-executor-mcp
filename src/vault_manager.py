import hvac

from src import check_env_key


class VaultManager:
    def __init__(self) -> None:
        """Initialize the Vault client with AppRole authentication."""
        use_appauth = bool(check_env_key("VAULT_USE_APPAUTH"))

        self._base_url = check_env_key("VAULT_BASE_URL")
        self._role_name = check_env_key("VAULT_ROLE_NAME")

        if use_appauth:
            self._role_id = check_env_key("VAULT_ROLE_ID")
            self._secret_id = check_env_key("VAULT_SECRET_ID")

            self._client = hvac.Client(url=self._base_url, timeout=30)
            response = self._client.auth.approle.login(
                role_id=self._role_id,
                secret_id=self._secret_id,
            )

            self._client.token = response["auth"]["client_token"]
        else:
            self._token = check_env_key("VAULT_TOKEN")
            self._client = hvac.Client(url=self._base_url, token=self._token, timeout=30)

    def get_credentials(self, machine_id: str) -> tuple[str, str]:
        """Retrieve the SSH private key and username from Vault."""
        response = self._client.secrets.kv.v2.read_secret_version(
            path=f"app/config/ssh/{machine_id}",
            mount_point=f"secrets-{self._role_name}",
        )

        data = response.get("data", {}).get("data")
        if not data:
            raise ValueError("There is no data field in response.")

        private_key = data.get("private_key")
        if not private_key:
            raise ValueError("There is no private_key field in data.")

        username = data.get("username")
        if not username:
            raise ValueError("There is no username field in data.")

        return username, private_key
