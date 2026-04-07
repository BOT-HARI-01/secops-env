# Copyright (c) 2026
# All rights reserved.

"""
SecOps Environment - Security Operations Task Environment for OpenEnv.

A real-world security operations environment that simulates common DevOps/SecOps tasks:
- PII Redaction: Identify and redact personally identifiable information
- Fix Public Access: Identify and fix overly permissive cloud storage
- Disable Ghost User: Find and disable orphaned/inactive user accounts

Example:
    >>> from secops_env import SecOpsEnv, SecOpsAction
    >>> with SecOpsEnv(base_url="http://localhost:8000").sync() as env:
    ...     result = env.reset(task="pii_redaction")
    ...     print(result.observation.objective)
    ...     result = env.step(SecOpsAction(action_type="finalize", redacted_text="..."))
    ...     print(result.reward)
"""

from .client import SecOpsEnv
from .models import SecOpsAction, SecOpsObservation, TaskConfig

__all__ = ["SecOpsEnv", "SecOpsAction", "SecOpsObservation", "TaskConfig"]
__version__ = "0.1.0"
