"""
SecOps Environment - Core Environment Logic.

Security operations environment implementing step/reset/state APIs.
Compatible with OpenEnv framework.
"""

import random
from typing import Any, Dict, Optional
from uuid import uuid4

# #0.01 = 1e-9


def _normalize_score(score: float) -> float:
    """Normalize score to be strictly between 0 and 1."""
    if score <= 0:
        return 0.01
    if score >= 1:
        return 0.99
    return score


from secops_env.models import (
    SecOpsAction,
    SecOpsObservation,
    EpisodeState,
    TaskType,
    TaskDifficulty,
    ActionType,
)
from secops_env.server.tasks.pii_redaction import PIIRedactionTask
from secops_env.server.tasks.public_access import PublicAccessTask
from secops_env.server.tasks.ghost_user import GhostUserTask
from secops_env.server.tasks.log_analysis import LogAnalysisTask
from secops_env.server.tasks.config_hardening import ConfigHardeningTask
from secops_env.server.graders.pii_grader import PIIGrader
from secops_env.server.graders.access_grader import AccessGrader
from secops_env.server.graders.user_grader import UserGrader
from secops_env.server.graders.log_grader import LogGrader
from secops_env.server.graders.config_grader import ConfigGrader


class SecOpsEnvironment:
    """
    Security Operations Environment for OpenEnv.

    Simulates real-world security operations tasks:
    - PII Redaction: Detect and redact personally identifiable information
    - Fix Public Access: Identify and fix overly permissive cloud storage
    - Disable Ghost User: Find and disable orphaned/inactive accounts

    Example:
        >>> env = SecOpsEnvironment()
        >>> obs = env.reset(task="pii_redaction")
        >>> print(obs.objective)
        >>> obs = env.step(SecOpsAction(...))
        >>> print(obs.reward)
    """

    TASK_REGISTRY = {
        TaskType.PII_REDACTION: PIIRedactionTask,
        TaskType.PUBLIC_ACCESS: PublicAccessTask,
        TaskType.GHOST_USER: GhostUserTask,
        TaskType.LOG_ANALYSIS: LogAnalysisTask,
        TaskType.CONFIG_HARDENING: ConfigHardeningTask,
    }

    GRADER_REGISTRY = {
        TaskType.PII_REDACTION: PIIGrader,
        TaskType.PUBLIC_ACCESS: AccessGrader,
        TaskType.GHOST_USER: UserGrader,
        TaskType.LOG_ANALYSIS: LogGrader,
        TaskType.CONFIG_HARDENING: ConfigGrader,
    }

    def __init__(self):
        """Initialize the SecOps environment."""
        self._state = EpisodeState(episode_id=str(uuid4()), step_count=0)
        self._current_task: Optional[object] = None
        self._current_task_type: Optional[TaskType] = None
        self._task_data: Dict[str, Any] = {}
        self._reward_history: list[float] = []
        self._reset_count = 0

    def reset(
        self,
        task: Optional[str] = None,
        difficulty: Optional[str] = None,
        seed: Optional[int] = None,
        **kwargs,
    ) -> SecOpsObservation:
        """
        Reset the environment for a new episode.

        Args:
            task: Task type override
            difficulty: Difficulty level override
            seed: Random seed for reproducibility
            **kwargs: Additional options

        Returns:
            Initial observation
        """
        if seed is not None:
            random.seed(seed)

        self._state = EpisodeState(episode_id=str(uuid4()), step_count=0)
        self._reset_count += 1
        self._reward_history = []

        task_type = TaskType(task) if task else random.choice(list(TaskType))
        self._current_task_type = task_type

        task_class = self.TASK_REGISTRY[task_type]
        self._current_task = task_class(difficulty=difficulty)

        self._task_data = self._current_task.generate_scenario()
        self._state.task_type = task_type.value
        self._state.task_data = self._task_data

        observation = self._build_observation(
            reward_accumulated=0.01,
            feedback="Environment ready. Begin security operations.",
        )

        return observation

    def step(self, action: SecOpsAction) -> SecOpsObservation:
        """
        Execute a step in the environment.

        Args:
            action: SecOpsAction to execute

        Returns:
            Observation after executing the action
        """
        self._state.step_count += 1

        action_task_type = (
            TaskType(action.task_type)
            if isinstance(action.task_type, str)
            else action.task_type
        )

        if action_task_type != self._current_task_type:
            return self._build_observation(
                done=False,
                feedback=f"Task mismatch. Current task: {self._current_task_type}, Action task: {action_task_type}",
            )

        grader_class = self.GRADER_REGISTRY[self._current_task_type]
        grader = grader_class()

        step_reward, feedback, done, success = self._current_task.execute_action(
            action=action, grader=grader, task_data=self._task_data
        )

        self._reward_history.append(step_reward)
        reward_accumulated = sum(self._reward_history)

        observation = self._build_observation(
            reward_accumulated=reward_accumulated,
            feedback=feedback,
            done=done,
            success=success,
        )

        return observation

    def _build_observation(
        self,
        reward_accumulated: float = 0.0,
        feedback: Optional[str] = None,
        done: bool = False,
        success: bool = False,
    ) -> SecOpsObservation:
        """Build observation from current state."""
        task_info = self._current_task.get_info() if self._current_task else {}

        partial_progress = self._calculate_partial_progress()

        observation = SecOpsObservation(
            task_type=self._current_task_type or TaskType.PII_REDACTION,
            task_difficulty=task_info.get("difficulty", TaskDifficulty.EASY),
            objective=task_info.get("objective", "Complete the security task"),
            context=self._task_data,
            available_actions=[a.value for a in ActionType],
            current_state=self._current_task.get_state() if self._current_task else {},
            partial_progress=partial_progress,
            step_count=self._state.step_count,
            max_steps=self._current_task.max_steps if self._current_task else 10,
            feedback=feedback,
            detected_issues=task_info.get("detected_issues", []),
            fixed_issues=task_info.get("fixed_issues", []),
            reward=reward_accumulated,
            done=done,
            success=success,
            metadata={
                "task_type": str(self._current_task_type)
                if self._current_task_type
                else None,
                "step_count": self._state.step_count,
                "success": success,
            },
        )

        return observation

    def _calculate_partial_progress(self) -> float:
        """Calculate partial progress toward task completion."""
        if not self._current_task:
            return 0.01

        task_info = self._current_task.get_info()
        fixed = len(task_info.get("fixed_issues", []))
        total = (
            self._current_task.total_issues
            if hasattr(self._current_task, "total_issues")
            else 1
        )

        return _normalize_score(min(0.99, fixed / max(1, total)))

    @property
    def state(self) -> EpisodeState:
        """Get current environment state."""
        return self._state

    def get_reward(self) -> float:
        """Get accumulated reward."""
        return sum(self._reward_history)
