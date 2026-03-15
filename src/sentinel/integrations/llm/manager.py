"""
LLM integration manager for AI-powered decision making.

This module provides a unified interface for LLM interactions,
supporting both local Ollama models and cloud-based fallback.
"""
import asyncio
import logging
from typing import Optional, Any
import httpx

logger = logging.getLogger(__name__)


class LLMManager:
    """
    Manages LLM interactions with local-first architecture.
    
    Uses Ollama for local inference by default, falling back to
    Claude API for complex queries requiring higher capability.
    
    Configuration:
        primary:
            type: "ollama"
            host: "http://localhost:11434"
            model: "llama3.1:8b"
        fallback:
            type: "anthropic"
            model: "claude-3-5-sonnet-20241022"
            api_key: "${ANTHROPIC_API_KEY}"
    
    Example:
        ```python
        manager = LLMManager(config)
        await manager.initialize()
        
        response = await manager.complete(
            prompt="Analyze this network traffic pattern",
            system_prompt="You are a network security analyst"
        )
        ```
    """
    
    def __init__(self, config: dict):
        """
        Initialize the LLM manager.
        
        Args:
            config: LLM configuration with primary and fallback settings
        """
        self.config = config
        
        # Primary (local) configuration
        primary = config.get("primary", {})
        self.primary_type = primary.get("type", "ollama")
        self.primary_host = primary.get("host", "http://localhost:11434")
        self.primary_model = primary.get("model", "llama3.1:8b")
        
        # Fallback (cloud) configuration
        fallback = config.get("fallback", {})
        self.fallback_type = fallback.get("type", "anthropic")
        self.fallback_model = fallback.get("model", "claude-3-5-sonnet-20241022")
        self.fallback_api_key = fallback.get("api_key")
        
        # Clients
        self._ollama_client: Optional[httpx.AsyncClient] = None
        self._anthropic_client: Optional[httpx.AsyncClient] = None
        
        # Stats
        self._local_calls = 0
        self._fallback_calls = 0
        self._total_tokens = 0
    
    async def initialize(self) -> None:
        """Initialize LLM clients."""
        # Initialize Ollama client
        self._ollama_client = httpx.AsyncClient(
            base_url=self.primary_host,
            timeout=60.0
        )
        
        # Check Ollama availability
        try:
            response = await self._ollama_client.get("/api/tags")
            if response.status_code == 200:
                models = response.json().get("models", [])
                model_names = [m.get("name", "") for m in models]
                if any(self.primary_model in name for name in model_names):
                    logger.info(f"Ollama ready with model {self.primary_model}")
                else:
                    logger.warning(
                        f"Model {self.primary_model} not found in Ollama. "
                        f"Available: {model_names}"
                    )
        except Exception as e:
            logger.warning(f"Ollama not available: {e}")
        
        # Initialize Anthropic client if configured
        if self.fallback_api_key:
            self._anthropic_client = httpx.AsyncClient(
                base_url="https://api.anthropic.com",
                headers={
                    "x-api-key": self.fallback_api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json"
                },
                timeout=120.0
            )
            logger.info("Anthropic fallback configured")
    
    async def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        model: Optional[str] = None,
        max_tokens: int = 1024,
        temperature: float = 0.7,
        prefer_local: bool = True
    ) -> str:
        """
        Generate completion from LLM.
        
        Args:
            prompt: User prompt
            system_prompt: Optional system prompt
            model: Specific model to use (overrides preference)
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature
            prefer_local: Whether to prefer local LLM
        
        Returns:
            Generated text response
        
        Raises:
            RuntimeError: If no LLM is available
        """
        # Determine which LLM to use
        use_local = prefer_local and self._ollama_client is not None
        
        if model:
            # If specific model requested, route accordingly
            if "claude" in model.lower() or "anthropic" in model.lower():
                use_local = False
            elif "llama" in model.lower() or "mistral" in model.lower():
                use_local = True
        
        if use_local:
            try:
                return await self._ollama_complete(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    model=model or self.primary_model,
                    max_tokens=max_tokens,
                    temperature=temperature
                )
            except Exception as e:
                logger.warning(f"Local LLM failed, falling back: {e}")
                if self._anthropic_client:
                    return await self._anthropic_complete(
                        prompt=prompt,
                        system_prompt=system_prompt,
                        model=model or self.fallback_model,
                        max_tokens=max_tokens,
                        temperature=temperature
                    )
                raise RuntimeError(f"LLM completion failed: {e}")
        else:
            if self._anthropic_client:
                return await self._anthropic_complete(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    model=model or self.fallback_model,
                    max_tokens=max_tokens,
                    temperature=temperature
                )
            # Fall back to local if cloud not available
            return await self._ollama_complete(
                prompt=prompt,
                system_prompt=system_prompt,
                model=model or self.primary_model,
                max_tokens=max_tokens,
                temperature=temperature
            )
    
    async def _ollama_complete(
        self,
        prompt: str,
        system_prompt: Optional[str],
        model: str,
        max_tokens: int,
        temperature: float
    ) -> str:
        """Generate completion using Ollama."""
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        response = await self._ollama_client.post(
            "/api/chat",
            json={
                "model": model,
                "messages": messages,
                "stream": False,
                "options": {
                    "num_predict": max_tokens,
                    "temperature": temperature
                }
            }
        )
        response.raise_for_status()
        
        result = response.json()
        self._local_calls += 1
        
        return result.get("message", {}).get("content", "")
    
    async def _anthropic_complete(
        self,
        prompt: str,
        system_prompt: Optional[str],
        model: str,
        max_tokens: int,
        temperature: float
    ) -> str:
        """Generate completion using Anthropic API."""
        payload = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}]
        }
        
        if system_prompt:
            payload["system"] = system_prompt
        
        response = await self._anthropic_client.post(
            "/v1/messages",
            json=payload
        )
        response.raise_for_status()
        
        result = response.json()
        self._fallback_calls += 1
        
        # Track token usage
        usage = result.get("usage", {})
        self._total_tokens += usage.get("input_tokens", 0)
        self._total_tokens += usage.get("output_tokens", 0)
        
        content = result.get("content", [])
        if content and content[0].get("type") == "text":
            return content[0].get("text", "")
        
        return ""
    
    async def analyze_decision(self, context: dict) -> dict:
        """
        Analyze a complex decision with full context.
        
        Used when agents need more sophisticated reasoning.
        
        Args:
            context: Decision context including agent, action, and state
        
        Returns:
            Analysis with recommendations
        """
        system_prompt = """You are a network security and automation expert.
Analyze the proposed action and provide a recommendation.
Consider security implications, potential risks, and best practices.
Respond with JSON containing:
- recommendation: "approve", "modify", or "reject"
- confidence: 0.0-1.0
- reasoning: explanation
- modifications: any suggested changes (if applicable)"""
        
        prompt = f"""Analyze this automated network action:

Agent: {context.get('agent')}
Action: {context.get('action', {}).get('action_type')}
Target: {context.get('action', {}).get('target_type')}/{context.get('action', {}).get('target_id')}
Reasoning: {context.get('action', {}).get('reasoning')}
Confidence: {context.get('action', {}).get('confidence')}

Current State:
{context.get('current_state', {})}

Trigger Event:
{context.get('trigger_event', 'None')}
"""
        
        response = await self.complete(
            prompt=prompt,
            system_prompt=system_prompt,
            prefer_local=False  # Use more capable model for decisions
        )
        
        # Parse response (would need proper JSON parsing)
        return {"response": response}
    
    async def close(self) -> None:
        """Close LLM clients."""
        if self._ollama_client:
            await self._ollama_client.aclose()
        if self._anthropic_client:
            await self._anthropic_client.aclose()
    
    @property
    def stats(self) -> dict:
        """Get usage statistics."""
        return {
            "local_calls": self._local_calls,
            "fallback_calls": self._fallback_calls,
            "total_tokens": self._total_tokens,
            "primary_model": self.primary_model,
            "fallback_model": self.fallback_model
        }
