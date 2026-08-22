"""Claude-generated defensive remediation plans for individual findings."""
import json
import os

from core.models import RemediationPlan

MODEL_NAME = "claude-sonnet-4-5-20250929"

SYSTEM_PROMPT = """You are a senior DevSecOps remediation engineer. Convert one confirmed
security finding into a practical, defensive implementation plan that a DevOps team can execute.
Return JSON only, with this exact shape:
{
  "summary": "one concise outcome-focused sentence",
  "priority": "immediate|high|medium|low",
  "steps": [
    {"title": "short step title", "action": "imperative action", "details": "precise implementation details", "commands": ["optional safe command"]}
  ],
  "validation": ["specific post-change verification"],
  "rollback": ["safe rollback action"]
}
Provide 3-6 ordered steps. Commands must be defensive configuration, patching, verification, or
deployment commands only. Never provide exploitation, persistence, evasion, credential theft, or
destructive actions. Do not invent exact package versions or environment details absent from the
finding; use clear placeholders where necessary. Keep the guidance specific to the evidence."""


def _parse_plan(raw_text: str) -> dict:
    text = raw_text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text
        text = text.rsplit("```", 1)[0]
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end < start:
        raise ValueError("AI response did not contain a JSON object")
    payload = json.loads(text[start:end + 1])
    return RemediationPlan.model_validate(payload).model_dump()


async def generate_remediation(scan_id: str, target: str, finding: dict) -> tuple[dict, str]:
    api_key = os.environ.get("EMERGENT_LLM_KEY")
    if not api_key:
        raise RuntimeError("AI service not configured")

    from emergentintegrations.llm.chat import LlmChat, StreamDone, TextDelta, UserMessage

    chat = LlmChat(
        api_key=api_key,
        session_id=f"remediation_{scan_id}_{finding.get('id', 'finding')}",
        system_message=SYSTEM_PROMPT,
    ).with_model("anthropic", MODEL_NAME)

    evidence = {
        "target": target,
        "finding_id": finding.get("id"),
        "severity": finding.get("severity"),
        "description": finding.get("description"),
        "source": finding.get("source"),
        "cvss": finding.get("cvss"),
        "references": finding.get("references", [])[:5],
        "baseline_remediation": finding.get("remediation"),
    }
    message = UserMessage(text=f"Create the remediation plan for this finding:\n{json.dumps(evidence, default=str)[:6000]}")
    chunks: list[str] = []
    async for event in chat.stream_message(message):
        if isinstance(event, TextDelta):
            chunks.append(event.content)
        elif isinstance(event, StreamDone):
            break

    if not chunks:
        raise ValueError("AI service returned an empty remediation")
    return _parse_plan("".join(chunks)), MODEL_NAME