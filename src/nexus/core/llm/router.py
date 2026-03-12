"""
LLM Router - Base class for domain-specific LLM routing.

Each C-level executive (CIO, CTO, COO) gets their own LLM router
with a model pool optimized for their domain. This prevents
bottlenecks and allows fine-grained control over model selection.

Architecture:
    ┌─────────────────────────────────────────────────────────────┐
    │                    LLMRouter (Base)                         │
    │  ┌─────────────────────────────────────────────────────┐   │
    │  │ Model Pool:                                          │   │
    │  │   - fast: Quick inference for real-time tasks       │   │
    │  │   - balanced: Good quality/speed trade-off          │   │
    │  │   - quality: Best output for complex tasks          │   │
    │  │   - specialized: Domain-specific models             │   │
    │  └─────────────────────────────────────────────────────┘   │
    │                                                             │
    │  Task Category → Model Tier mapping (configurable)          │
    └─────────────────────────────────────────────────────────────┘

Usage:
    router = CIORouter(config)
    await router.initialize()

    # Router selects model based on task category
    response = await router.complete(
        task_category="threat_detection",
        prompt="Analyze this traffic pattern...",
        context={"severity": "high"}
    )
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any, Optional, Callable
import httpx

logger = logging.getLogger(__name__)


class ModelTier(str, Enum):
    """Model capability tiers for routing decisions."""

    FAST = "fast"  # Low latency, smaller models (7B)
    BALANCED = "balanced"  # Good trade-off (13B-22B)
    QUALITY = "quality"  # Best output (70B+ or cloud)
    SPECIALIZED = "specialized"  # Domain-specific models


class ModelProvider(str, Enum):
    """Supported LLM providers."""

    OLLAMA = "ollama"
    ANTHROPIC = "anthropic"
    OPENAI = "openai"


@dataclass
class ModelConfig:
    """Configuration for a single model in the pool."""

    name: str
    provider: ModelProvider
    tier: ModelTier

    # Provider-specific settings
    host: str = "http://localhost:11434"  # For Ollama
    api_key: str = ""  # For cloud providers

    # Model parameters
    max_tokens: int = 4096
    temperature: float = 0.7
    timeout: float = 60.0

    # Routing hints
    specializations: List[str] = field(default_factory=list)  # e.g., ["code", "security"]
    max_concurrent: int = 5
    priority: int = 0  # Higher = preferred when multiple match

    # Runtime state
    available: bool = True
    current_load: int = 0


@dataclass
class RoutingResult:
    """Result of model selection."""

    model: ModelConfig
    reason: str
    fallback_chain: List[str] = field(default_factory=list)


@dataclass
class CompletionResult:
    """Result of LLM completion."""

    text: str
    model_used: str
    provider: ModelProvider
    tokens_used: int = 0
    latency_ms: float = 0.0
    from_cache: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


class LLMRouter(ABC):
    """
    Abstract base class for domain-specific LLM routing.

    Each C-level executive extends this to define their own
    model pool and task-to-tier mappings.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the router.

        Args:
            config: Router configuration including model pool
        """
        self.config = config
        self._models: Dict[str, ModelConfig] = {}
        self._clients: Dict[ModelProvider, httpx.AsyncClient] = {}
        self._initialized = False

        # Metrics
        self._requests_by_tier: Dict[ModelTier, int] = {t: 0 for t in ModelTier}
        self._requests_by_model: Dict[str, int] = {}
        self._total_tokens = 0
        self._cache_hits = 0

        # Simple response cache (task_hash -> response)
        self._cache: Dict[str, CompletionResult] = {}
        self._cache_ttl = config.get("cache_ttl", 300)  # 5 min default

    @property
    @abstractmethod
    def domain(self) -> str:
        """Domain this router serves (e.g., 'cio', 'cto')."""
        pass

    @property
    @abstractmethod
    def default_model_pool(self) -> List[ModelConfig]:
        """Default model pool for this domain."""
        pass

    @abstractmethod
    def get_task_tier(self, task_category: str, context: Dict[str, Any]) -> ModelTier:
        """
        Map a task category to a model tier.

        Override in subclasses to implement domain-specific routing logic.

        Args:
            task_category: Type of task (e.g., "threat_detection", "code_review")
            context: Additional context for routing decisions

        Returns:
            Appropriate model tier for this task
        """
        pass

    async def initialize(self) -> None:
        """Initialize the router and verify model availability."""
        if self._initialized:
            return

        # Load model pool from config or use defaults
        pool_config = self.config.get("model_pool", [])
        if pool_config:
            self._load_model_pool(pool_config)
        else:
            for model in self.default_model_pool:
                self._models[model.name] = model

        # Initialize provider clients
        await self._init_clients()

        # Check model availability
        await self._verify_models()

        self._initialized = True
        logger.info(
            f"{self.domain.upper()} LLMRouter initialized with "
            f"{len(self._models)} models across {len(self._clients)} providers"
        )

    def _load_model_pool(self, pool_config: List[Dict]) -> None:
        """Load model pool from configuration."""
        for cfg in pool_config:
            model = ModelConfig(
                name=cfg["name"],
                provider=ModelProvider(cfg.get("provider", "ollama")),
                tier=ModelTier(cfg.get("tier", "balanced")),
                host=cfg.get("host", "http://localhost:11434"),
                api_key=cfg.get("api_key", ""),
                max_tokens=cfg.get("max_tokens", 4096),
                temperature=cfg.get("temperature", 0.7),
                timeout=cfg.get("timeout", 60.0),
                specializations=cfg.get("specializations", []),
                max_concurrent=cfg.get("max_concurrent", 5),
                priority=cfg.get("priority", 0),
            )
            self._models[model.name] = model

    async def _init_clients(self) -> None:
        """Initialize HTTP clients for each provider."""
        providers_needed = set(m.provider for m in self._models.values())

        for provider in providers_needed:
            if provider == ModelProvider.OLLAMA:
                # Get host from any Ollama model (they should share the same host)
                ollama_models = [
                    m for m in self._models.values() if m.provider == ModelProvider.OLLAMA
                ]
                if ollama_models:
                    host = ollama_models[0].host
                    self._clients[ModelProvider.OLLAMA] = httpx.AsyncClient(
                        base_url=host, timeout=120.0
                    )

            elif provider == ModelProvider.ANTHROPIC:
                # Get API key from any Anthropic model
                anthropic_models = [
                    m for m in self._models.values() if m.provider == ModelProvider.ANTHROPIC
                ]
                if anthropic_models and anthropic_models[0].api_key:
                    self._clients[ModelProvider.ANTHROPIC] = httpx.AsyncClient(
                        base_url="https://api.anthropic.com",
                        headers={
                            "x-api-key": anthropic_models[0].api_key,
                            "anthropic-version": "2023-06-01",
                            "content-type": "application/json",
                        },
                        timeout=120.0,
                    )

            elif provider == ModelProvider.OPENAI:
                openai_models = [
                    m for m in self._models.values() if m.provider == ModelProvider.OPENAI
                ]
                if openai_models and openai_models[0].api_key:
                    self._clients[ModelProvider.OPENAI] = httpx.AsyncClient(
                        base_url="https://api.openai.com/v1",
                        headers={
                            "Authorization": f"Bearer {openai_models[0].api_key}",
                            "content-type": "application/json",
                        },
                        timeout=120.0,
                    )

    async def _verify_models(self) -> None:
        """Verify which models are actually available."""
        if ModelProvider.OLLAMA in self._clients:
            try:
                response = await self._clients[ModelProvider.OLLAMA].get("/api/tags")
                if response.status_code == 200:
                    available = response.json().get("models", [])
                    available_names = [m.get("name", "") for m in available]

                    for model in self._models.values():
                        if model.provider == ModelProvider.OLLAMA:
                            # Check if model name matches (handles tags like :latest)
                            model.available = any(
                                model.name in name or name in model.name for name in available_names
                            )
                            if not model.available:
                                logger.warning(f"Ollama model {model.name} not available")
            except Exception as e:
                logger.warning(f"Could not verify Ollama models: {e}")
                for model in self._models.values():
                    if model.provider == ModelProvider.OLLAMA:
                        model.available = False

        # Cloud providers assumed available if client exists
        for model in self._models.values():
            if model.provider in [ModelProvider.ANTHROPIC, ModelProvider.OPENAI]:
                model.available = model.provider in self._clients

    def select_model(
        self,
        task_category: str,
        context: Dict[str, Any] = None,
        preferred_tier: Optional[ModelTier] = None,
    ) -> RoutingResult:
        """
        Select the best model for a task.

        Args:
            task_category: Type of task
            context: Additional routing context
            preferred_tier: Override tier selection

        Returns:
            RoutingResult with selected model and fallback chain
        """
        context = context or {}

        # Determine target tier
        tier = preferred_tier or self.get_task_tier(task_category, context)

        # Find available models in this tier
        candidates = [
            m
            for m in self._models.values()
            if m.available and m.tier == tier and m.current_load < m.max_concurrent
        ]

        # Check for specialization match
        if task_category:
            specialized = [
                m for m in candidates if any(s in task_category.lower() for s in m.specializations)
            ]
            if specialized:
                candidates = specialized

        # Sort by priority (higher first), then by current load (lower first)
        candidates.sort(key=lambda m: (-m.priority, m.current_load))

        if not candidates:
            # Build fallback chain through tiers
            fallback_order = [
                ModelTier.BALANCED,
                ModelTier.QUALITY,
                ModelTier.FAST,
                ModelTier.SPECIALIZED,
            ]

            for fallback_tier in fallback_order:
                if fallback_tier == tier:
                    continue
                fallback_candidates = [
                    m for m in self._models.values() if m.available and m.tier == fallback_tier
                ]
                if fallback_candidates:
                    candidates = fallback_candidates
                    break

        if not candidates:
            raise RuntimeError(f"No models available for task: {task_category}")

        selected = candidates[0]

        # Build fallback chain
        fallback_chain = [m.name for m in candidates[1:3]]

        return RoutingResult(
            model=selected,
            reason=f"Selected {selected.tier.value} tier model for {task_category}",
            fallback_chain=fallback_chain,
        )

    async def complete(
        self,
        prompt: str,
        task_category: str = "general",
        system_prompt: Optional[str] = None,
        context: Dict[str, Any] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        use_cache: bool = True,
    ) -> CompletionResult:
        """
        Generate completion using the best available model.

        Args:
            prompt: User prompt
            task_category: Task type for model selection
            system_prompt: Optional system prompt
            context: Routing context
            max_tokens: Override model default
            temperature: Override model default
            use_cache: Whether to use response cache

        Returns:
            CompletionResult with response and metadata
        """
        if not self._initialized:
            await self.initialize()

        context = context or {}

        # Check cache
        if use_cache:
            cache_key = self._cache_key(prompt, task_category, system_prompt)
            if cache_key in self._cache:
                self._cache_hits += 1
                cached = self._cache[cache_key]
                cached.from_cache = True
                return cached

        # Select model
        routing = self.select_model(task_category, context)
        model = routing.model

        # Track load
        model.current_load += 1
        self._requests_by_tier[model.tier] += 1
        self._requests_by_model[model.name] = self._requests_by_model.get(model.name, 0) + 1

        try:
            import time

            start = time.time()

            # Route to appropriate provider
            if model.provider == ModelProvider.OLLAMA:
                result = await self._ollama_complete(
                    model,
                    prompt,
                    system_prompt,
                    max_tokens or model.max_tokens,
                    temperature if temperature is not None else model.temperature,
                )
            elif model.provider == ModelProvider.ANTHROPIC:
                result = await self._anthropic_complete(
                    model,
                    prompt,
                    system_prompt,
                    max_tokens or model.max_tokens,
                    temperature if temperature is not None else model.temperature,
                )
            elif model.provider == ModelProvider.OPENAI:
                result = await self._openai_complete(
                    model,
                    prompt,
                    system_prompt,
                    max_tokens or model.max_tokens,
                    temperature if temperature is not None else model.temperature,
                )
            else:
                raise ValueError(f"Unsupported provider: {model.provider}")

            result.latency_ms = (time.time() - start) * 1000
            result.metadata["task_category"] = task_category
            result.metadata["routing_reason"] = routing.reason

            # Update metrics
            self._total_tokens += result.tokens_used

            # Cache result
            if use_cache:
                self._cache[cache_key] = result

            return result

        except Exception as e:
            logger.error(f"Completion failed with {model.name}: {e}")

            # Try fallback
            for fallback_name in routing.fallback_chain:
                if fallback_name in self._models:
                    fallback_model = self._models[fallback_name]
                    logger.info(f"Falling back to {fallback_name}")
                    try:
                        return await self._complete_with_model(
                            fallback_model,
                            prompt,
                            system_prompt,
                            max_tokens,
                            temperature,
                            task_category,
                        )
                    except Exception as fallback_e:
                        logger.error(f"Fallback {fallback_name} also failed: {fallback_e}")

            raise RuntimeError(f"All models failed for task {task_category}: {e}")
        finally:
            model.current_load -= 1

    async def _complete_with_model(
        self,
        model: ModelConfig,
        prompt: str,
        system_prompt: Optional[str],
        max_tokens: Optional[int],
        temperature: Optional[float],
        task_category: str,
    ) -> CompletionResult:
        """Complete with a specific model."""
        import time

        start = time.time()

        if model.provider == ModelProvider.OLLAMA:
            result = await self._ollama_complete(
                model,
                prompt,
                system_prompt,
                max_tokens or model.max_tokens,
                temperature if temperature is not None else model.temperature,
            )
        elif model.provider == ModelProvider.ANTHROPIC:
            result = await self._anthropic_complete(
                model,
                prompt,
                system_prompt,
                max_tokens or model.max_tokens,
                temperature if temperature is not None else model.temperature,
            )
        elif model.provider == ModelProvider.OPENAI:
            result = await self._openai_complete(
                model,
                prompt,
                system_prompt,
                max_tokens or model.max_tokens,
                temperature if temperature is not None else model.temperature,
            )
        else:
            raise ValueError(f"Unsupported provider: {model.provider}")

        result.latency_ms = (time.time() - start) * 1000
        result.metadata["task_category"] = task_category
        return result

    async def _ollama_complete(
        self,
        model: ModelConfig,
        prompt: str,
        system_prompt: Optional[str],
        max_tokens: int,
        temperature: float,
    ) -> CompletionResult:
        """Generate completion using Ollama."""
        client = self._clients.get(ModelProvider.OLLAMA)
        if not client:
            raise RuntimeError("Ollama client not initialized")

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        response = await client.post(
            "/api/chat",
            json={
                "model": model.name,
                "messages": messages,
                "stream": False,
                "options": {"num_predict": max_tokens, "temperature": temperature},
            },
            timeout=model.timeout,
        )
        response.raise_for_status()

        result = response.json()
        text = result.get("message", {}).get("content", "")

        # Ollama doesn't always return token counts
        tokens = result.get("eval_count", 0) + result.get("prompt_eval_count", 0)

        return CompletionResult(
            text=text,
            model_used=model.name,
            provider=ModelProvider.OLLAMA,
            tokens_used=tokens,
            metadata={"raw_response": result},
        )

    async def _anthropic_complete(
        self,
        model: ModelConfig,
        prompt: str,
        system_prompt: Optional[str],
        max_tokens: int,
        temperature: float,
    ) -> CompletionResult:
        """Generate completion using Anthropic API."""
        client = self._clients.get(ModelProvider.ANTHROPIC)
        if not client:
            raise RuntimeError("Anthropic client not initialized")

        payload = {
            "model": model.name,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }

        if system_prompt:
            payload["system"] = system_prompt

        if temperature is not None:
            payload["temperature"] = temperature

        response = await client.post("/v1/messages", json=payload, timeout=model.timeout)
        response.raise_for_status()

        result = response.json()

        content = result.get("content", [])
        text = ""
        if content and content[0].get("type") == "text":
            text = content[0].get("text", "")

        usage = result.get("usage", {})
        tokens = usage.get("input_tokens", 0) + usage.get("output_tokens", 0)

        return CompletionResult(
            text=text,
            model_used=model.name,
            provider=ModelProvider.ANTHROPIC,
            tokens_used=tokens,
            metadata={"usage": usage},
        )

    async def _openai_complete(
        self,
        model: ModelConfig,
        prompt: str,
        system_prompt: Optional[str],
        max_tokens: int,
        temperature: float,
    ) -> CompletionResult:
        """Generate completion using OpenAI API."""
        client = self._clients.get(ModelProvider.OPENAI)
        if not client:
            raise RuntimeError("OpenAI client not initialized")

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": model.name,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }

        response = await client.post("/chat/completions", json=payload, timeout=model.timeout)
        response.raise_for_status()

        result = response.json()

        choices = result.get("choices", [])
        text = ""
        if choices:
            text = choices[0].get("message", {}).get("content", "")

        usage = result.get("usage", {})
        tokens = usage.get("total_tokens", 0)

        return CompletionResult(
            text=text,
            model_used=model.name,
            provider=ModelProvider.OPENAI,
            tokens_used=tokens,
            metadata={"usage": usage},
        )

    def _cache_key(self, prompt: str, task_category: str, system_prompt: Optional[str]) -> str:
        """Generate cache key for a request."""
        import hashlib

        content = f"{task_category}:{system_prompt or ''}:{prompt}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    async def close(self) -> None:
        """Close all HTTP clients."""
        for client in self._clients.values():
            await client.aclose()
        self._clients.clear()

    @property
    def stats(self) -> Dict[str, Any]:
        """Get router statistics."""
        return {
            "domain": self.domain,
            "models_available": sum(1 for m in self._models.values() if m.available),
            "models_total": len(self._models),
            "requests_by_tier": {t.value: c for t, c in self._requests_by_tier.items()},
            "requests_by_model": self._requests_by_model,
            "total_tokens": self._total_tokens,
            "cache_hits": self._cache_hits,
            "cache_size": len(self._cache),
        }

    def add_model(self, model: ModelConfig) -> None:
        """Add a model to the pool at runtime."""
        self._models[model.name] = model
        logger.info(f"Added model {model.name} to {self.domain} router")

    def remove_model(self, name: str) -> None:
        """Remove a model from the pool."""
        if name in self._models:
            del self._models[name]
            logger.info(f"Removed model {name} from {self.domain} router")
