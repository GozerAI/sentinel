"""
CTO LLM Router - Development-optimized model routing for Forge.

The CTO router manages a model pool optimized for software development:
- Code generation and completion (quality models)
- Code review and analysis (balanced models)
- Quick fixes and refactoring (fast models)
- Architecture design (quality models)
- Documentation generation (balanced models)

Task Categories:
    code_generate       → QUALITY tier (output quality critical)
    code_review         → BALANCED tier
    code_fix           → FAST tier
    refactor           → BALANCED tier
    architecture       → QUALITY tier
    documentation      → BALANCED tier
    test_generate      → BALANCED tier
"""

import logging
from typing import Dict, List, Any

from nexus.core.llm.router import (
    LLMRouter,
    ModelConfig,
    ModelTier,
    ModelProvider,
)

logger = logging.getLogger(__name__)


class CTORouter(LLMRouter):
    """
    CTO-specific LLM router for software development operations.

    Optimized for:
    - High-quality code generation
    - Thorough code review
    - Quick bug fixes and refactoring
    - Architecture and design decisions
    - Test generation

    Model Pool Strategy:
    - FAST: DeepSeek Coder 6.7B, StarCoder2 for quick tasks
    - BALANCED: Codestral 22B for review/refactor
    - QUALITY: Claude Sonnet for generation/architecture
    - SPECIALIZED: Language-specific models
    """

    @property
    def domain(self) -> str:
        return "cto"

    @property
    def default_model_pool(self) -> List[ModelConfig]:
        """Default development-optimized model pool."""
        return [
            # FAST tier - Quick fixes and completions
            ModelConfig(
                name="deepseek-coder:6.7b",
                provider=ModelProvider.OLLAMA,
                tier=ModelTier.FAST,
                max_tokens=2048,
                temperature=0.2,
                timeout=30.0,
                specializations=["fix", "complete", "snippet"],
                max_concurrent=10,
                priority=10,
            ),
            ModelConfig(
                name="starcoder2:7b",
                provider=ModelProvider.OLLAMA,
                tier=ModelTier.FAST,
                max_tokens=2048,
                temperature=0.2,
                timeout=30.0,
                specializations=["python", "javascript", "quick"],
                max_concurrent=10,
                priority=5,
            ),
            ModelConfig(
                name="qwen2.5-coder:7b",
                provider=ModelProvider.OLLAMA,
                tier=ModelTier.FAST,
                max_tokens=2048,
                temperature=0.2,
                timeout=30.0,
                specializations=["code", "debug"],
                max_concurrent=10,
                priority=3,
            ),
            # BALANCED tier - Review and refactor
            ModelConfig(
                name="codestral:22b",
                provider=ModelProvider.OLLAMA,
                tier=ModelTier.BALANCED,
                max_tokens=4096,
                temperature=0.3,
                timeout=90.0,
                specializations=["review", "refactor", "analyze"],
                max_concurrent=3,
                priority=10,
            ),
            ModelConfig(
                name="deepseek-coder:33b",
                provider=ModelProvider.OLLAMA,
                tier=ModelTier.BALANCED,
                max_tokens=4096,
                temperature=0.3,
                timeout=120.0,
                specializations=["test", "documentation"],
                max_concurrent=2,
                priority=5,
            ),
            ModelConfig(
                name="qwen2.5-coder:32b",
                provider=ModelProvider.OLLAMA,
                tier=ModelTier.BALANCED,
                max_tokens=4096,
                temperature=0.3,
                timeout=120.0,
                specializations=["complex", "multilang"],
                max_concurrent=2,
                priority=3,
            ),
            # QUALITY tier - Code generation and architecture
            ModelConfig(
                name="claude-3-5-sonnet-20241022",
                provider=ModelProvider.ANTHROPIC,
                tier=ModelTier.QUALITY,
                max_tokens=8192,
                temperature=0.5,
                timeout=180.0,
                specializations=["generate", "architecture", "design", "feature"],
                max_concurrent=5,
                priority=10,
            ),
            ModelConfig(
                name="claude-3-5-haiku-20241022",
                provider=ModelProvider.ANTHROPIC,
                tier=ModelTier.QUALITY,
                max_tokens=4096,
                temperature=0.5,
                timeout=120.0,
                specializations=["explain", "document"],
                max_concurrent=5,
                priority=5,
            ),
            ModelConfig(
                name="gpt-4o",
                provider=ModelProvider.OPENAI,
                tier=ModelTier.QUALITY,
                max_tokens=4096,
                temperature=0.5,
                timeout=120.0,
                specializations=["generate", "complex"],
                max_concurrent=5,
                priority=3,
            ),
            # SPECIALIZED tier - Language-specific
            ModelConfig(
                name="codellama:34b-python",
                provider=ModelProvider.OLLAMA,
                tier=ModelTier.SPECIALIZED,
                max_tokens=4096,
                temperature=0.2,
                timeout=120.0,
                specializations=["python"],
                max_concurrent=2,
                priority=10,
            ),
        ]

    def get_task_tier(self, task_category: str, context: Dict[str, Any]) -> ModelTier:
        """
        Map development task categories to model tiers.

        Routing Logic:
        - Code generation → QUALITY (output quality critical)
        - Review/refactor → BALANCED (thorough but fast)
        - Quick fixes → FAST (speed matters)
        - Architecture → QUALITY (reasoning critical)
        """
        category = task_category.lower()

        # Check for language-specific routing
        language = context.get("language", "").lower()
        if language == "python" and "generate" in category:
            # Check if we have Python specialist available
            for model in self._models.values():
                if model.available and "python" in model.specializations:
                    return ModelTier.SPECIALIZED

        # Check complexity hint
        complexity = context.get("complexity", "").lower()
        if complexity == "high":
            return ModelTier.QUALITY
        elif complexity == "low":
            return ModelTier.FAST

        # QUALITY tier mappings - High-stakes code tasks
        quality_tasks = [
            "code_generate",
            "code_gen",
            "feature_implement",
            "architecture",
            "design",
            "api_design",
            "system_design",
            "complex_implement",
            "security_review",
            "performance_critical",
        ]
        if any(task in category for task in quality_tasks):
            return ModelTier.QUALITY

        # FAST tier mappings - Quick operations
        fast_tasks = [
            "code_fix",
            "quick_fix",
            "bug_fix",
            "typo",
            "format",
            "lint_fix",
            "complete",
            "snippet",
            "inline_suggest",
        ]
        if any(task in category for task in fast_tasks):
            return ModelTier.FAST

        # BALANCED tier - Default for most development tasks
        balanced_tasks = [
            "code_review",
            "review",
            "refactor",
            "optimize",
            "test_generate",
            "test_gen",
            "documentation",
            "document",
            "explain",
            "analyze",
            "dependency",
        ]
        if any(task in category for task in balanced_tasks):
            return ModelTier.BALANCED

        # Default to BALANCED
        return ModelTier.BALANCED

    # =========================================================================
    # CTO-SPECIFIC HELPER METHODS
    # =========================================================================

    async def generate_code(
        self,
        specification: str,
        language: str = "python",
        context: Dict[str, Any] = None,
        existing_code: str = None,
    ) -> Dict[str, Any]:
        """
        Generate code from a specification.

        Uses QUALITY tier for best output.

        Args:
            specification: What to generate
            language: Target programming language
            context: Additional context
            existing_code: Existing code to extend

        Returns:
            Generated code and metadata
        """
        context = context or {}
        context["language"] = language

        system_prompt = f"""You are an expert {language} developer.
Generate clean, well-documented, production-ready code.
Follow {language} best practices and idioms.
Include appropriate error handling and type hints where applicable.
Output ONLY the code, no explanations unless specifically asked."""

        prompt = f"""Generate {language} code for the following:

Specification:
{specification}
"""

        if existing_code:
            prompt += f"""
Existing Code Context:
```{language}
{existing_code[:2000]}
```

Extend or integrate with the existing code appropriately.
"""

        if context.get("style_guide"):
            prompt += f"\nFollow this style guide: {context['style_guide']}"

        result = await self.complete(
            prompt=prompt,
            task_category="code_generate",
            system_prompt=system_prompt,
            context=context,
            temperature=0.3,  # Moderate temp for creativity with consistency
        )

        return {
            "code": result.text,
            "language": language,
            "model_used": result.model_used,
            "latency_ms": result.latency_ms,
        }

    async def review_code(
        self,
        code: str,
        language: str = "python",
        review_focus: List[str] = None,
        context: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """
        Review code for issues and improvements.

        Args:
            code: Code to review
            language: Programming language
            review_focus: Areas to focus on (security, performance, style, etc.)
            context: Additional context

        Returns:
            Review findings
        """
        focus_areas = review_focus or ["security", "performance", "readability", "bugs"]
        focus_text = ", ".join(focus_areas)

        system_prompt = f"""You are a senior {language} code reviewer.
Analyze code for: {focus_text}.

Output JSON with:
- issues: list of {{severity, category, line, description, suggestion}}
- strengths: list of good practices found
- overall_quality: score 1-10
- summary: brief overall assessment"""

        prompt = f"""Review this {language} code:

```{language}
{code}
```

Focus areas: {focus_text}
Provide thorough review with specific line references where applicable."""

        result = await self.complete(
            prompt=prompt,
            task_category="code_review",
            system_prompt=system_prompt,
            context=context or {},
        )

        return {
            "review": result.text,
            "language": language,
            "focus_areas": focus_areas,
            "model_used": result.model_used,
            "latency_ms": result.latency_ms,
        }

    async def fix_code(
        self,
        code: str,
        error: str = None,
        issue_description: str = None,
        language: str = "python",
        context: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """
        Fix code issues quickly.

        Uses FAST tier for rapid response.

        Args:
            code: Code with issues
            error: Error message if available
            issue_description: Description of the problem
            language: Programming language
            context: Additional context

        Returns:
            Fixed code
        """
        system_prompt = f"""You are a {language} debugging expert.
Fix the code issue quickly and accurately.
Output ONLY the corrected code, no explanations.
Make minimal changes - only fix what's broken."""

        prompt = f"""Fix this {language} code:

```{language}
{code}
```
"""

        if error:
            prompt += f"\nError: {error}"
        if issue_description:
            prompt += f"\nProblem: {issue_description}"

        result = await self.complete(
            prompt=prompt,
            task_category="code_fix",
            system_prompt=system_prompt,
            context=context or {},
            temperature=0.1,  # Very low for precise fixes
        )

        return {
            "fixed_code": result.text,
            "language": language,
            "model_used": result.model_used,
            "latency_ms": result.latency_ms,
        }

    async def refactor_code(
        self,
        code: str,
        refactor_goals: List[str] = None,
        language: str = "python",
        context: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """
        Refactor code for better quality.

        Args:
            code: Code to refactor
            refactor_goals: Goals like "readability", "performance", "modularity"
            language: Programming language
            context: Additional context

        Returns:
            Refactored code with explanation
        """
        goals = refactor_goals or ["readability", "maintainability"]
        goals_text = ", ".join(goals)

        system_prompt = f"""You are a {language} refactoring expert.
Refactor the code to improve: {goals_text}.
Maintain the same functionality while improving code quality.
Output the refactored code followed by a brief explanation of changes."""

        prompt = f"""Refactor this {language} code:

```{language}
{code}
```

Goals: {goals_text}

Preserve all existing functionality while improving the code structure."""

        result = await self.complete(
            prompt=prompt,
            task_category="refactor",
            system_prompt=system_prompt,
            context=context or {},
        )

        return {
            "refactored_code": result.text,
            "goals": goals,
            "language": language,
            "model_used": result.model_used,
            "latency_ms": result.latency_ms,
        }

    async def generate_tests(
        self,
        code: str,
        language: str = "python",
        test_framework: str = None,
        coverage_goals: List[str] = None,
        context: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """
        Generate tests for code.

        Args:
            code: Code to test
            language: Programming language
            test_framework: Framework to use (pytest, jest, etc.)
            coverage_goals: What to cover (unit, edge_cases, integration)
            context: Additional context

        Returns:
            Generated tests
        """
        framework = test_framework or ("pytest" if language == "python" else "jest")
        coverage = coverage_goals or ["unit", "edge_cases"]
        coverage_text = ", ".join(coverage)

        system_prompt = f"""You are a {language} testing expert using {framework}.
Generate comprehensive tests covering: {coverage_text}.
Follow testing best practices with descriptive test names.
Output ONLY the test code."""

        prompt = f"""Generate {framework} tests for this {language} code:

```{language}
{code}
```

Coverage goals: {coverage_text}

Include tests for:
- Normal operation
- Edge cases
- Error handling
- Boundary conditions"""

        result = await self.complete(
            prompt=prompt,
            task_category="test_generate",
            system_prompt=system_prompt,
            context=context or {},
        )

        return {
            "tests": result.text,
            "framework": framework,
            "language": language,
            "coverage_goals": coverage,
            "model_used": result.model_used,
            "latency_ms": result.latency_ms,
        }

    async def design_architecture(
        self,
        requirements: str,
        constraints: List[str] = None,
        tech_stack: List[str] = None,
        context: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """
        Design system architecture.

        Uses QUALITY tier for complex reasoning.

        Args:
            requirements: System requirements
            constraints: Technical constraints
            tech_stack: Preferred technologies
            context: Additional context

        Returns:
            Architecture design
        """
        constraints_text = "\n".join([f"- {c}" for c in (constraints or [])])
        stack_text = ", ".join(tech_stack or ["flexible"])

        system_prompt = """You are a senior software architect.
Design a robust, scalable architecture based on requirements.

Output should include:
- Overview: High-level architecture description
- Components: Key components and their responsibilities
- Interfaces: How components communicate
- Data Flow: How data moves through the system
- Technology Choices: Recommended technologies with rationale
- Trade-offs: Key decisions and their trade-offs
- Diagram: ASCII diagram of the architecture"""

        prompt = f"""Design an architecture for:

Requirements:
{requirements}
"""
        if constraints:
            prompt += f"\nConstraints:\n{constraints_text}"
        if tech_stack:
            prompt += f"\nPreferred Tech Stack: {stack_text}"

        result = await self.complete(
            prompt=prompt,
            task_category="architecture",
            system_prompt=system_prompt,
            context=context or {},
            max_tokens=4096,
        )

        return {
            "architecture": result.text,
            "model_used": result.model_used,
            "latency_ms": result.latency_ms,
        }

    async def generate_documentation(
        self,
        code: str,
        doc_type: str = "api",
        language: str = "python",
        context: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """
        Generate documentation for code.

        Args:
            code: Code to document
            doc_type: Type of documentation (api, readme, inline, docstring)
            language: Programming language
            context: Additional context

        Returns:
            Generated documentation
        """
        doc_prompts = {
            "api": "Generate API documentation with endpoints, parameters, responses, and examples.",
            "readme": "Generate a README with overview, installation, usage, and examples.",
            "inline": "Add inline comments explaining complex logic.",
            "docstring": "Generate comprehensive docstrings for all functions and classes.",
        }

        system_prompt = f"""You are a technical writer specializing in {language} documentation.
{doc_prompts.get(doc_type, doc_prompts['api'])}
Be clear, concise, and include practical examples."""

        prompt = f"""Generate {doc_type} documentation for this {language} code:

```{language}
{code}
```"""

        result = await self.complete(
            prompt=prompt,
            task_category="documentation",
            system_prompt=system_prompt,
            context=context or {},
        )

        return {
            "documentation": result.text,
            "doc_type": doc_type,
            "language": language,
            "model_used": result.model_used,
            "latency_ms": result.latency_ms,
        }
