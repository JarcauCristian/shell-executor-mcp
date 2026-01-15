import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import psycopg2
from psycopg2.extensions import connection as PgConnection


@dataclass
class Database:
    """PostgreSQL database handler for command event logging."""

    _connection: Optional[PgConnection] = field(default=None, init=False, repr=False)

    def _get_connection_params(self) -> dict[str, str]:
        """Get database connection parameters from environment variables."""
        return {
            "host": os.environ.get("POSTGRES_HOST", "localhost"),
            "port": os.environ.get("POSTGRES_PORT", "5432"),
            "database": os.environ.get("POSTGRES_DB", "shell_executor"),
            "user": os.environ.get("POSTGRES_USER", "postgres"),
            "password": os.environ.get("POSTGRES_PASSWORD", ""),
        }

    def open(self) -> None:
        """Open a connection to the PostgreSQL database."""
        if self._connection is not None and not self._connection.closed:
            return

        params = self._get_connection_params()
        self._connection = psycopg2.connect(**params)
        self._create_table()

    def close(self) -> None:
        """Close the database connection."""
        if self._connection is not None and not self._connection.closed:
            self._connection.close()
            self._connection = None

    def _create_table(self) -> None:
        """Create the command_events table if it doesn't exist."""
        if self._connection is None:
            raise RuntimeError("Database connection is not open")

        create_table_sql = """
        CREATE TABLE IF NOT EXISTS command_events (
            event_id TEXT PRIMARY KEY,
            machine_id TEXT NOT NULL,
            command TEXT NOT NULL,
            exit_code INTEGER,
            stdout TEXT,
            stderr TEXT,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            duration_ms INTEGER,
            username TEXT NOT NULL,
            hostname TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        """

        with self._connection.cursor() as cursor:
            cursor.execute(create_table_sql)
            self._connection.commit()

    def _create_command_event(
        self,
        machine_id: str,
        command: str,
        username: str,
        hostname: str,
        started_at: str,
    ) -> str:
        """
        Create a new command event entry when a command starts executing.

        Returns the event_id (UUID4) of the created entry.
        """
        if self._connection is None:
            raise RuntimeError("Database connection is not open")

        event_id = str(uuid.uuid4())

        insert_sql = """
        INSERT INTO command_events (
            event_id, machine_id, command, username, hostname, started_at
        ) VALUES (%s, %s, %s, %s, %s, %s);
        """

        with self._connection.cursor() as cursor:
            cursor.execute(
                insert_sql,
                (
                    event_id,
                    machine_id,
                    command,
                    username,
                    hostname,
                    started_at,
                ),
            )
            self._connection.commit()

        return event_id

    def _update_command_event(
        self,
        event_id: str,
        exit_code: int,
        stdout: str,
        stderr: str,
        started_at: str,
    ) -> None:
        """
        Update an existing command event with the execution results.

        Args:
            event_id: The UUID of the command event to update
            exit_code: The exit code of the command
            stdout: Standard output from the command
            stderr: Standard error from the command
            started_at: The ISO timestamp when the command started
        """
        if self._connection is None:
            raise RuntimeError("Database connection is not open")

        completed_at = datetime.now(timezone.utc).isoformat()

        started_dt = datetime.fromisoformat(started_at)
        completed_dt = datetime.fromisoformat(completed_at)
        duration_ms = int((completed_dt - started_dt).total_seconds() * 1000)

        update_sql = """
        UPDATE command_events
        SET exit_code = %s,
            stdout = %s,
            stderr = %s,
            completed_at = %s,
            duration_ms = %s
        WHERE event_id = %s;
        """

        with self._connection.cursor() as cursor:
            cursor.execute(
                update_sql,
                (
                    exit_code,
                    stdout,
                    stderr,
                    completed_at,
                    duration_ms,
                    event_id,
                ),
            )
            self._connection.commit()

    def log_command_execution(
        self,
        machine_id: str,
        command: str,
        username: str,
        hostname: str,
        exit_code: int,
        stdout: str,
        stderr: str,
        started_at: str,
    ) -> str:
        """
        Convenience method to create and immediately update a command event.

        Returns the event_id of the created entry.
        """
        event_id = self._create_command_event(
            machine_id=machine_id,
            command=command,
            username=username,
            hostname=hostname,
            started_at=started_at,
        )

        self._update_command_event(
            event_id=event_id,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            started_at=started_at,
        )

        return event_id
