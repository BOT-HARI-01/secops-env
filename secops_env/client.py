"""
SecOps Environment Client.

Client for connecting to a SecOps Environment server.
"""

import httpx
from typing import Optional, Dict, Any

from secops_env.models import SecOpsAction, SecOpsObservation, StepResult


class SecOpsEnv:
    """
    Client for the SecOps Environment.

    Provides access to security operations tasks:
    - pii_redaction: PII detection and redaction
    - public_access: Cloud storage security
    - ghost_user: Account lifecycle management

    Example:
        >>> # Sync usage (recommended)
        >>> env = SecOpsEnv(base_url="http://localhost:8000")
        >>> result = env.reset(task="pii_redaction")
        >>> print(result.observation.objective)
        >>> result = env.step(SecOpsAction(...))
        >>> print(result.reward)
        >>> env.close()
    """

    def __init__(self, base_url: str = "http://localhost:8000", timeout: float = 30.0):
        """Initialize the client with base URL."""
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._client = httpx.Client(base_url=self.base_url, timeout=timeout)

    def reset(
        self,
        task: Optional[str] = None,
        difficulty: Optional[str] = None,
        seed: Optional[int] = None,
        **kwargs,
    ) -> StepResult:
        """
        Reset the environment for a new episode.

        Args:
            task: Task type ("pii_redaction", "public_access", "ghost_user")
            difficulty: Difficulty level ("easy", "medium", "hard")
            seed: Random seed for reproducibility
            **kwargs: Additional options

        Returns:
            StepResult with initial observation
        """
        params = {}
        if task is not None:
            params["task"] = task
        if difficulty is not None:
            params["difficulty"] = difficulty
        if seed is not None:
            params["seed"] = seed
        params.update(kwargs)

        response = self._client.post("/reset", json=params)
        response.raise_for_status()
        data = response.json()

        obs_data = data.get("observation", {})
        return StepResult(
            observation=SecOpsObservation(**obs_data),
            reward=data.get("reward", 0.0),
            done=data.get("done", False),
            info=data.get("info", {}),
        )

    def step(self, action: SecOpsAction) -> StepResult:
        """
        Execute an action in the environment.

        Args:
            action: SecOpsAction to execute

        Returns:
            StepResult with observation, reward, and done flag
        """
        payload = action.model_dump()
        response = self._client.post("/step", json={"action": payload})
        response.raise_for_status()
        data = response.json()

        obs_data = data.get("observation", {})
        return StepResult(
            observation=SecOpsObservation(**obs_data),
            reward=data.get("reward", 0.0),
            done=data.get("done", False),
            info=data.get("info", {}),
        )

    def get_state(self) -> Dict[str, Any]:
        """
        Get current environment state.

        Returns:
            Dictionary with episode metadata
        """
        response = self._client.get("/state")
        response.raise_for_status()
        return response.json()

    def close(self):
        """Close the HTTP client."""
        self._client.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
