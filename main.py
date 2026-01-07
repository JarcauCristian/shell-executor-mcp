from pathlib import Path

from mcp.server.fastmcp import Context, FastMCP
from mcp.server.session import ServerSession

from src.models import CommandResponse
from src.shell_executor import ShellExecutor
from src.shell_verifier import ShellVerifier
from src.vault_manager import VaultManager

DEFAULT_USERNAME = "ubuntu"
DEFAULT_KEY_PATH = "executor.key"

mcp = FastMCP(name="Secure shell executor tool with verification.")


@mcp.tool()
def execute_single_command(command: str, hostname: str, machine_id: str) -> CommandResponse | dict[str, str]:
    """Execute a single shell command onto the specified hostname"""
    verifier = ShellVerifier()
    response = verifier.verify_script(command)

    if not response.safe_to_execute or response.risk_level in ["high", "critical"]:
        return {"result": f"Command `{command}` is not safe to execute, aborting...", "reason": response.json()}

    executor = ShellExecutor(hostname, DEFAULT_USERNAME, DEFAULT_KEY_PATH)
        
    return executor.execute_command(command)


@mcp.tool()
async def execute_commands(
    task_name: str,
    ctx: Context[ServerSession, None],
    commands: list[str],
    hostname: str,
    machine_id: str
) -> str:
    """Execute a task with progress updates."""
    await ctx.info(f"Starting: {task_name}")

    verifier = ShellVerifier()
    script = "\n".join(commands)

    response = verifier.verify_script(commands)
    if not response.safe_to_execute or response.risk_level in ["high", "critical"]:
        return {
            "result": f"Script\n`{script}`\n is not safe to execute, aborting...",
            "reason": response.json()
        }

    executor = ShellExecutor(hostname, DEFAULT_USERNAME, DEFAULT_KEY_PATH)

    steps = len(commands)
    commands_results = []
    for idx, command in enumerate(commands):
        progress = (idx + 1) / steps
        await ctx.report_progress(
            progress=progress,
            total=1.0,
            message=f"Executing command {idx}/{steps}",
        )
        
        commands_results.append(executor.execute_command(command))

        await ctx.debug(f"Completed command {command}")

    return commands_results


if __name__ == "__main__":
    vault_manager = VaultManager()

    private_key = vault_manager.get_ssh_key()
    with Path(DEFAULT_KEY_PATH).open(mode="w") as fp:
        fp.write(private_key)
