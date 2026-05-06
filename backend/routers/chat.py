"""Claude AI chat routes."""
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException

from core.db import db
from core.models import ChatMessage, ChatResponse
from core.security import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter()

SYSTEM_PROMPT = """You are PentestAI, an advanced AI assistant for ethical penetration testing and cybersecurity. You help security professionals with:

1. **Reconnaissance**: Suggest tools (Nmap, Shodan, whois, dig, recon-ng) and interpret scan results
2. **Vulnerability Assessment**: Identify potential vulnerabilities from scan data, suggest exploits
3. **Network Analysis**: Help analyze traffic patterns, identify anomalies
4. **Exploitation Guidance**: Provide ethical guidance on Metasploit, Empire, and other frameworks
5. **Reporting**: Help generate professional security reports

IMPORTANT RULES:
- Only assist with AUTHORIZED penetration testing
- Always emphasize legal and ethical considerations
- Provide educational content for learning purposes
- Suggest proper authorization before any testing
- Format responses with clear headers and bullet points
- Include command examples when relevant

When suggesting commands, format them in code blocks for easy copying."""


@router.post("/chat", response_model=ChatResponse)
async def chat_with_ai(message: ChatMessage, current_user: dict = Depends(get_current_user)):
    session_id = message.session_id or str(uuid.uuid4())
    api_key = os.environ.get('EMERGENT_LLM_KEY')
    if not api_key:
        raise HTTPException(status_code=500, detail="AI service not configured")

    from emergentintegrations.llm.chat import LlmChat, UserMessage  # local import to keep startup snappy

    try:
        chat = LlmChat(
            api_key=api_key,
            session_id=f"{current_user['id']}_{session_id}",
            system_message=SYSTEM_PROMPT,
        ).with_model("anthropic", "claude-sonnet-4-5-20250929")

        response = await chat.send_message(UserMessage(text=message.message))

        await db.chat_history.insert_one({
            "id": str(uuid.uuid4()),
            "user_id": current_user["id"],
            "session_id": session_id,
            "message": message.message,
            "response": response,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
        return ChatResponse(response=response, session_id=session_id)
    except Exception as e:
        logger.error(f"AI Chat error: {e}")
        raise HTTPException(status_code=500, detail=f"AI service error: {e}")


@router.get("/chat/history")
async def get_chat_history(session_id: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    query = {"user_id": current_user["id"]}
    if session_id:
        query["session_id"] = session_id
    history = await db.chat_history.find(query, {"_id": 0}).sort("created_at", -1).to_list(50)
    return {"history": history}
