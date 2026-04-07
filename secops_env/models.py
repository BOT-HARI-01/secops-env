"""
SecOps Environment - Typed Models

Pydantic models for actions, observations, and state management.
"""

from typing import Any, Dict, List, Optional
from enum import Enum
from pydantic import BaseModel, Field, ConfigDict


class TaskType(str, Enum):
    """Available security operations tasks."""

    PII_REDACTION = "pii_redaction"
    PUBLIC_ACCESS = "public_access"
    GHOST_USER = "ghost_user"
    LOG_ANALYSIS = "log_analysis"
    CONFIG_HARDENING = "config_hardening"


class TaskDifficulty(str, Enum):
    """Task difficulty levels."""

    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"


class ActionType(str, Enum):
    """Available action types."""

    ANALYZE = "analyze"
    IDENTIFY = "identify"
    APPLY_FIX = "apply_fix"
    FINALIZE = "finalize"
    NOOP = "noop"
    CLASSIFY = "classify"
    PRIORITIZE = "prioritize"
    REVIEW = "review"
    IDENTIFY_ISSUES = "identify_issues"
    SUGGEST_FIXES = "suggest_fixes"
    APPLY_FIXES = "apply_fixes"


class SecOpsAction(BaseModel):
    """Action model for security operations tasks."""

    task_type: TaskType = Field(..., description="The task being performed")
    action_type: ActionType = Field(..., description="Type of action to take")

    redacted_text: Optional[str] = Field(None, description="Redacted text for PII task")
    public_resources: Optional[List[str]] = Field(
        None, description="Resources identified as public"
    )
    fixed_resources: Optional[List[str]] = Field(
        None, description="Resources that were fixed"
    )
    ghost_users: Optional[List[str]] = Field(None, description="Ghost users identified")
    disabled_users: Optional[List[str]] = Field(
        None, description="Users that were disabled"
    )
    classification: Optional[str] = Field(
        None, description="Log classification (e.g., MALWARE, TRUE_POSITIVE, etc.)"
    )
    severity: Optional[str] = Field(
        None, description="Severity level (LOW, MEDIUM, HIGH, CRITICAL)"
    )
    log_alerts: Optional[List[Dict[str, Any]]] = Field(
        None, description="Analyzed log alerts with classifications"
    )
    config_issues: Optional[List[Dict[str, Any]]] = Field(
        None, description="Configuration issues identified"
    )
    hardened_config: Optional[str] = Field(
        None, description="Hardened configuration output"
    )

    confidence: Optional[float] = Field(
        None, ge=0.0, le=1.0, description="Confidence score"
    )
    reasoning: Optional[str] = Field(None, description="Reasoning for the action")

    model_config = ConfigDict(
        use_enum_values=True,
        extra="allow",  # Allow extra fields for flexibility
    )


class SecOpsObservation(BaseModel):
    """Observation model for security operations tasks."""

    task_type: TaskType = Field(..., description="Current task type")
    task_difficulty: TaskDifficulty = Field(..., description="Task difficulty level")
    objective: str = Field(..., description="Clear objective description")

    context: Dict[str, Any] = Field(
        default_factory=dict, description="Scenario context data"
    )
    available_actions: List[str] = Field(
        default_factory=list, description="Actions available"
    )
    current_state: Dict[str, Any] = Field(
        default_factory=dict, description="Current state"
    )

    partial_progress: float = Field(
        0.0, ge=0.0, le=1.0, description="Partial completion score"
    )
    step_count: int = Field(0, ge=0, description="Current step number")
    max_steps: int = Field(10, description="Maximum steps allowed")

    feedback: Optional[str] = Field(None, description="Feedback on last action")
    detected_issues: List[str] = Field(
        default_factory=list, description="Issues detected so far"
    )
    fixed_issues: List[str] = Field(
        default_factory=list, description="Issues fixed so far"
    )

    reward: float = Field(0.0, description="Reward for this step")
    done: bool = Field(False, description="Episode completed flag")
    success: bool = Field(False, description="Task success flag")
    metadata: Dict[str, Any] = Field(
        default_factory=dict, description="Additional metadata"
    )

    model_config = ConfigDict(use_enum_values=True, extra="allow")


class StepResult(BaseModel):
    """Result from a step() call."""

    observation: SecOpsObservation
    reward: float = Field(..., description="Reward for this step")
    done: bool = Field(..., description="Episode done flag")
    info: Dict[str, Any] = Field(default_factory=dict, description="Additional info")


class EpisodeState(BaseModel):
    """Episode state tracking (renamed to avoid conflict with OpenEnv State)."""

    episode_id: str
    step_count: int = 0
    task_type: Optional[str] = None
    task_data: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(use_enum_values=True, extra="allow")


class TaskConfig(BaseModel):
    """Configuration for a specific task."""

    task_type: TaskType
    difficulty: TaskDifficulty
    objective: str
    context: Dict[str, Any]
    success_criteria: Dict[str, Any]
    max_steps: int = 10

    model_config = ConfigDict(use_enum_values=True)
