"""
Public Access Task - Medium Security Task.

Identify and fix overly permissive cloud storage (S3 bucket) access.
"""

import random
from typing import Any, Dict, List, Optional, Tuple
from secops_env.models import SecOpsAction, TaskDifficulty, ActionType

EPSILON = 0.01


class PublicAccessTask:
    """
    Public Access Task - Medium Difficulty.

    Objective: Identify S3 buckets with public access and fix their permissions.

    Success Criteria:
    - All public buckets correctly identified
    - All public buckets set to private/block public access
    - No false positives (private buckets correctly left alone)

    Reward Structure:
    - +0.15 per correctly identified public resource
    - +0.4 bonus for fixing all public resources
    - -0.1 per missed public resource
    - -0.2 per false positive (marking private as public)
    """

    def __init__(self, difficulty: Optional[str] = None):
        """Initialize the public access task."""
        self.max_steps = 7
        self.difficulty = (
            TaskDifficulty.MEDIUM if difficulty is None else TaskDifficulty(difficulty)
        )
        self.objective = "Identify S3 buckets with public access enabled and fix their permissions to block public access."

        self._resources = []
        self._expected_public = []
        self._identified_public = []
        self._fixed_buckets = []
        self._total_issues = 0

    def generate_scenario(self) -> Dict[str, Any]:
        """Generate a public access scenario."""
        all_buckets = [
            {"name": "logs-prod-2024", "public": False, "type": "s3"},
            {"name": "customer-data-backup", "public": True, "type": "s3"},
            {"name": "website-static-assets", "public": True, "type": "s3"},
            {"name": "internal-reports-q4", "public": False, "type": "s3"},
            {"name": "marketing-assets", "public": False, "type": "s3"},
            {"name": "user-uploads-prod", "public": True, "type": "s3"},
            {"name": "config-backups", "public": False, "type": "s3"},
            {"name": "analytics-data", "public": True, "type": "s3"},
            {"name": "ml-models-prod", "public": False, "type": "s3"},
            {"name": "public-documentation", "public": True, "type": "s3"},
            {"name": "employee-records", "public": False, "type": "s3"},
            {"name": "temp-storage-share", "public": True, "type": "s3"},
            {"name": "application-logs", "public": False, "type": "s3"},
            {"name": "public-media-bucket", "public": True, "type": "s3"},
            {"name": "database-exports", "public": False, "type": "s3"},
            {"name": "api-keys-storage", "public": False, "type": "s3"},
            {"name": "cdn-assets-prod", "public": True, "type": "s3"},
            {"name": "user-avatars", "public": True, "type": "s3"},
            {"name": "backup-archive-2023", "public": False, "type": "s3"},
            {"name": "audit-logs-secure", "public": False, "type": "s3"},
            {"name": "mobile-app-assets", "public": True, "type": "s3"},
            {"name": "billing-invoices", "public": False, "type": "s3"},
            {"name": "shared-team-files", "public": True, "type": "s3"},
            {"name": "product-images", "public": True, "type": "s3"},
        ]

        scenario_buckets = random.sample(all_buckets, min(8, len(all_buckets)))

        self._resources = scenario_buckets
        self._expected_public = [b["name"] for b in scenario_buckets if b["public"]]
        self._identified_public = []
        self._fixed_buckets = []
        self._total_issues = len(self._expected_public)

        return {
            "resources": scenario_buckets,
            "instructions": "Identify buckets with public access and apply fixes to block public access.",
        }

    def execute_action(
        self, action: SecOpsAction, grader, task_data: Dict[str, Any]
    ) -> Tuple[float, str, bool, bool]:
        """
        Execute a public access action.

        Returns:
            Tuple of (reward, feedback, done, success)
        """
        reward = EPSILON
        feedback = ""
        done = False
        success = False

        if action.action_type == ActionType.ANALYZE:
            feedback = (
                f"Analyzing {len(self._resources)} resources for public access..."
            )

        elif action.action_type == ActionType.IDENTIFY:
            if action.public_resources:
                self._identified_public = action.public_resources
                score = grader.grade_identification(
                    identified=self._identified_public, expected=self._expected_public
                )
                reward = score * 0.5
                feedback = f"Identified {len(self._identified_public)} public resources. Score: {score:.2f}"
            else:
                feedback = "No public resources identified."

        elif action.action_type == ActionType.APPLY_FIX:
            if action.fixed_resources:
                self._fixed_buckets = action.fixed_resources
                score = grader.grade_fix(
                    fixed=self._fixed_buckets,
                    expected_public=self._expected_public,
                    identified=self._identified_public,
                )
                reward = score * 0.3
                feedback = f"Applied fixes to {len(self._fixed_buckets)} resources. Score: {score:.2f}"
            else:
                feedback = "No fixes applied."

        elif action.action_type == ActionType.FINALIZE:
            if action.fixed_resources:
                self._fixed_buckets = action.fixed_resources

            if not self._fixed_buckets and action.public_resources:
                self._fixed_buckets = action.public_resources

            score = grader.grade_fix(
                fixed=self._fixed_buckets,
                expected_public=self._expected_public,
                identified=self._identified_public,
            )
            reward = score

            if score >= 0.9:
                feedback = f"Perfect! All public access fixed. Score: {score:.2f}"
                success = True
                done = True
            elif score >= 0.5:
                feedback = f"Good progress. Some buckets may still be public. Score: {score:.2f}"
            else:
                feedback = f"Action required. Public buckets remain unfixed. Score: {score:.2f}"

        else:
            feedback = f"Unknown action type: {action.action_type}"

        return reward, feedback, done, success

    def get_info(self) -> Dict[str, Any]:
        """Get current task information."""
        return {
            "difficulty": self.difficulty,
            "objective": self.objective,
            "detected_issues": self._identified_public,
            "fixed_issues": self._fixed_buckets,
            "total_issues": self._total_issues,
        }

    def get_state(self) -> Dict[str, Any]:
        """Get current task state."""
        return {
            "total_resources": len(self._resources),
            "expected_public": len(self._expected_public),
            "identified_public": len(self._identified_public),
            "fixed_buckets": len(self._fixed_buckets),
            "remaining_public": len(self._expected_public) - len(self._fixed_buckets),
        }
