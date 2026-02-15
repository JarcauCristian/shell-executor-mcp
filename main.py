from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Literal

import click
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.session import ServerSession

from src.database import Database
from src.models import AppContext, CommandResponse
from src.shell_executor import ShellExecutor
from src.shell_verifier import ShellVerifier


@asynccontextmanager
async def lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    verifier = ShellVerifier()
    executor = ShellExecutor()
    db = Database()

    try:
        db.open()
        yield AppContext(verifier=verifier, executor=executor, db=db)
    finally:
        db.close()


mcp = FastMCP(name="Secure shell executor tool with verification.", lifespan=lifespan)


@mcp.tool(
    name="execute-command",
    description="""
    Execute a single commands on a specified hostname identified by a machine id in an async manner.
    """
)
def execute_single_command(
    command: str,
    hostname: str,
    machine_id: str,
    ctx: Context[ServerSession, AppContext],
) -> CommandResponse | dict[str, str | None]:
    """Execute a single shell command onto the specified hostname"""
    executor = ctx.request_context.lifespan_context.executor
    verifier = ctx.request_context.lifespan_context.verifier
    db = ctx.request_context.lifespan_context.db
    response = verifier.verify_script(command)

    if response is None:
        return {"result": "Failed to validate the script, aborting...", "reason": None}

    if not response.safe_to_execute or response.risk_level in ["high", "critical"]:
        return {
            "result": f"Command `{command}` is not safe to execute, aborting...",
            "reason": response.model_dump_json(),
        }

    executor.set_connection_from_machine_id(hostname, machine_id)

    started_at = datetime.now(timezone.utc).isoformat()
    result = executor.execute_command(command)

    _ = db.log_command_execution(
        machine_id=machine_id,
        command=command,
        hostname=hostname,
        username=executor.get_username(),
        exit_code=result.exit_code,
        stdout=result.stdout,
        stderr=result.stderr,
        started_at=started_at,
    )

    return result


@mcp.tool(
    name="execute-commands",
    description="""
    Execute multiple commands on a specified hostname identified by a machine id in an async manner.
    """
)
async def execute_commands(
    task_name: str,
    ctx: Context[ServerSession, AppContext],
    commands: list[str],
    hostname: str,
    machine_id: str,
) -> list[CommandResponse] | dict[str, str | None]:
    """Execute a task with progress updates."""
    await ctx.info(f"Starting: {task_name}")

    executor = ctx.request_context.lifespan_context.executor
    verifier = ctx.request_context.lifespan_context.verifier
    db = ctx.request_context.lifespan_context.db
    script = "\n".join(commands)

    response = verifier.verify_script(script)
    if response is None:
        return {"result": "Failed to validate the script, aborting...", "reason": None}

    if not response.safe_to_execute or response.risk_level in ["high", "critical"]:
        return {
            "result": f"Script\n`{script}`\n is not safe to execute, aborting...",
            "reason": response.model_dump_json(),
        }

    executor.set_connection_from_machine_id(hostname, machine_id)

    steps = len(commands)
    commands_results: list[CommandResponse] = []
    for idx, command in enumerate(commands):
        progress = (idx + 1) / steps
        await ctx.report_progress(
            progress=progress,
            total=1.0,
        )

        started_at = datetime.now(timezone.utc).isoformat()
        result = executor.execute_command(command)

        _ = db.log_command_execution(
            machine_id=machine_id,
            command=command,
            username=executor.get_username(),
            hostname=hostname,
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            started_at=started_at,
        )

        commands_results.append(result)

        await ctx.debug(f"Completed command {command}")

    return commands_results


@click.command("shell-executor")
@click.option(
    "--mcp-transport",
    required=False,
    type=click.Choice(["stdio", "sse", "streamable-http"]),
    default="stdio",
)
@click.option(
    "--port",
    required=False,
    type=int,
    default=8000,
    help="Port to run the server on (only used with http or sse transport)",
)
def main(
    mcp_transport: Literal["stdio", "sse", "streamable-http"],
    port: int,
) -> None:
    """Secure Shell Executor MCP Server."""
    match mcp_transport:
        case "streamable-http" | "sse":
            mcp.settings.port = port

    mcp.run(transport=mcp_transport)


if __name__ == "__main__":
    main()
