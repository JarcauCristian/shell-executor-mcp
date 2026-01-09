import types
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

import click
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.session import ServerSession

from src.models import CommandResponse, AppContext
from src.shell_executor import ShellExecutor
from src.shell_verifier import ShellVerifier


@asynccontextmanager
async def lifespan(server: FastMCP) -> types.AsyncGeneratorType:
    verifier = ShellVerifier()
    executor = ShellExecutor()
    db = None

    try:
        yield AppContext(
            verifier=verifier,
            executor=executor,
            db=db
        )
    finally:
        ...


mcp = FastMCP(name="Secure shell executor tool with verification.", lifespan=lifespan)


@mcp.tool()
def execute_single_command(
    command: str,
    hostname: str,
    machine_id: str,
    ctx: Context[ServerSession, AppContext]
) -> CommandResponse | dict[str, str | None]:
    """Execute a single shell command onto the specified hostname"""
    executor = ctx.request_context.lifespan_context.executor
    verifier = ctx.request_context.lifespan_context.verifier
    response = verifier.verify_script(command)

    if response is None:
        return {
            "result": "Failed to validate the script, aborting...",
            "reason": None
        }

    if not response.safe_to_execute or response.risk_level in ["high", "critical"]:  # ty:ignore[possibly-missing-attribute]
        return {
            "result": f"Command `{command}` is not safe to execute, aborting...",
            "reason": response.model_dump_json()
        }  # ty:ignore[possibly-missing-attribute]

    executor.set_connection_from_machine_id(hostname, machine_id)
        
    response = executor.execute_command(command)
    # TODO: Save the result of the command to the database for auditing.
    return response


@mcp.tool(
    name="execute-commands",
    description="Execute multiple commands on a specified hostname identified by a machine id in an async manner.",
    structured_output=True,
)
async def execute_commands(
    task_name: str,
    ctx: Context[ServerSession, AppContext],
    commands: list[str],
    hostname: str,
    machine_id: str
) -> list[CommandResponse] | dict[str, str | None]:
    """Execute a task with progress updates."""
    await ctx.info(f"Starting: {task_name}")

    executor = ctx.request_context.lifespan_context.executor
    verifier = ctx.request_context.lifespan_context.verifier
    script = "\n".join(commands)

    response = verifier.verify_script(script)
    if response is None:
        return {
            "result": "Failed to validate the script, aborting...",
            "reason": None
        }

    if not response.safe_to_execute or response.risk_level in ["high", "critical"]:  # ty:ignore[possibly-missing-attribute]
        return {
            "result": f"Script\n`{script}`\n is not safe to execute, aborting...",
            "reason": response.model_dump_json()  # ty:ignore[possibly-missing-attribute]
        }

    executor.set_connection_from_machine_id(hostname, machine_id)

    steps = len(commands)
    commands_results: list[CommandResponse] = []
    for idx, command in enumerate(commands):
        progress = (idx + 1) / steps
        await ctx.report_progress(
            progress=progress,
            total=1.0,
            message=f"Executing command {idx}/{steps}",
        )
        
        result = executor.execute_command(command)
        # TODO: Save the result of the command to the database for auditing.
        commands_results.append(result)

        await ctx.debug(f"Completed command {command}")

    return commands_results


@click.command("shell-executor")
@click.option(
    "--mcp-transport",
    required=False,
    type=click.Choice(["stdio", "sse", "streamable-http"]),
    default=Path("executor.key")
)
def main(
    username: str,
    key_path: Path,
    mcp_transport: Literal["stdio", "sse", "streamable-http"],
) -> None:
    """Secure Shell Executor MCP Server."""
    mcp.run(transport=mcp_transport)


if __name__ == "__main__":
    main()

