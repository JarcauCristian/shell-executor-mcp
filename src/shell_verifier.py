import os
import json
from typing import Optional

import aisuite as ai

from src.models import ShellScriptAnalysis


class ShellVerifier:
    def __init__(self, model: Optional[str] = "groq:openai/gpt-oss-20b"):
        apiKey = os.getenv("GROQ_API_KEY")
        if apiKey is None:
            raise ValueError("groq API key environment variable not present")

        schema = ShellScriptAnalysis.model_json_schema()

        self._client = ai.Client()
        self._model = model
        self._prompt = f"""
        You are a security expert. Analyze this bash script for potential security threats.
        Look for:
        - Malicious commands or patterns
        - Data exfiltration attempts
        - Privilege escalation
        - Resource exhaustion
        - Unintended side effects
        - Obfuscated code

        If the script is not malicious, but still can be harmful mark it as safe_to_execute and rise the risk_level.

        Always respond in JSON format with no other text or explanation beside following this schema:
        {json.dumps(schema, indent=2)}
        """

    def verify_script(self, script: str) -> ShellScriptAnalysis| None:
        if script == "":
            raise ValueError("script value should not be empty")

        messages = [
            {
                "role": "system",
                "content": self._prompt,
            },
            {
                "role": "user",
                "content": f"""
                Anaylze this script:
                {script}
                """,
            },
        ]

        try:
            response = self._client.chat.completions.create(
                model=self._model, messages=messages, temperature=0.1
            )
        except Exception as ex:
            raise RuntimeError("failed to execute the complition") from ex

        response_text = response.choices[0].message.content

        if "```json" in response_text:
            response_text = response_text.split("```json")[1].split("```")[0].strip()
        elif "```" in response_text:
            response_text = response_text.split("```")[1].split("```")[0].strip()

        shell_analysis = None
        try:
            shell_analysis_data = json.loads(response_text)
            shell_analysis = ShellScriptAnalysis(**shell_analysis_data)
        except Exception as ex:
            raise RuntimeError(
                f"failed to convert the LLM response to {ShellScriptAnalysis.__name__}"
            ) from ex

        return shell_analysis
