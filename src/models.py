from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, Field
from src.shell_verifier import ShellVerifier


class ShellScriptAnalysis(BaseModel):
    risk_level: Literal["low", "medium", "high", "critical"] = Field(
        description="Risk level of executing the shell script"
    )
    threats_found: list[str] = Field(
        description="A list of threats that are found in the shell script"
    )
    dangerous_lines: list[int] = Field(
        description="A list of number representing dangerous lines in the script"
    )
    explanation: str = Field(
        description="A textual description about the threat identified and the decision process in which the threat was indetified"
    )
    safe_to_execute: bool = Field(
        description="If it is safe to execute the script than true else false"
    )


class CommandResponse(BaseModel):
    stdout: str = Field(description="Stdout of the command.")
    stderr: str = Field(description="Stderr of the command.")
    exit_code: int = Field(description="Exit status code for executing the command.")


@dataclass
class AppContext:
    verifier: ShellVerifier
    db: None
