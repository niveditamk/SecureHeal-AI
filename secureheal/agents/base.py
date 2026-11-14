"""Abstract base class for all SecureHeal-AI agents."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from secureheal.config import settings
from secureheal.orchestrator.state import SecureHealState

logger = logging.getLogger("secureheal.agents")


class BaseAgent(ABC):
    """Base agent providing LLM access and audit logging."""

    name: str = "base_agent"
    role: str = "Base Agent"

    def get_llm(self, temperature: float = 0.1) -> Any:
        """Return a LangChain chat model based on configuration."""
        model_name = settings.MODEL_NAME

        if settings.GOOGLE_API_KEY and model_name.startswith("gemini"):
            from langchain_google_genai import ChatGoogleGenerativeAI

            return ChatGoogleGenerativeAI(
                model=model_name,
                google_api_key=settings.GOOGLE_API_KEY,
                temperature=temperature,
            )
        elif settings.OPENAI_API_KEY:
            from langchain_openai import ChatOpenAI

            return ChatOpenAI(
                model=model_name if not model_name.startswith("gemini") else "gpt-4o",
                api_key=settings.OPENAI_API_KEY,
                temperature=temperature,
            )
        else:
            raise RuntimeError(
                "No LLM API key configured. Set GOOGLE_API_KEY or OPENAI_API_KEY in .env"
            )

    def log_action(
        self,
        state: SecureHealState,
        action: str,
        details: dict | None = None,
    ) -> list[dict]:
        """Append an audit entry to the workflow log and return the updated log."""
        entry = {
            "phase": state.get("current_phase", "unknown"),
            "agent": self.name,
            "role": self.role,
            "action": action,
            "details": details or {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        log = list(state.get("workflow_log", []))
        log.append(entry)
        logger.info("[%s] %s — %s", self.name, action, details or "")
        return log

    @abstractmethod
    async def execute(self, state: SecureHealState) -> dict:
        """Run the agent's logic and return state updates.

        Subclasses must implement this.  Return a dict of state keys to update.
        """
        ...
