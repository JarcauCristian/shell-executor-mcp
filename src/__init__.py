"""Shell Executor module."""

import os


def check_env_key(env_key: str) -> str:
    """
    Utility function for checking if an environment variable exists.

    Raises:
        ValueError - If the environment variable is not present.
    """

    env_value = os.getenv(env_key)
    if not env_value:
        raise ValueError(f"Environment {env_key} required, but is empty.")

    return env_value
