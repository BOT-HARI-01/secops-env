"""
Ghost User Task - Hard Security Task.

Identify and disable orphaned/inactive user accounts.
"""

import random
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from secops_env.models import SecOpsAction, TaskDifficulty, ActionType

EPSILON = 0.01


class GhostUserTask:
    """
    Ghost User Task - Hard Difficulty.

    Objective: Identify orphaned/inactive user accounts and disable them.

    Ghost User Criteria:
    - No login in 90+ days
    - No active resources associated
    - No role in recent deployments
    - Account created > 1 year ago and never used

    Success Criteria:
    - All ghost users correctly identified
    - No false positives (active users disabled)
    - All ghost users disabled

    Reward Structure:
    - +0.1 per correctly identified ghost user
    - +0.3 bonus for correctly disabling all identified users
    - -0.2 per incorrect disable (active user marked as ghost)
    """

    def __init__(self, difficulty: Optional[str] = None):
        """Initialize the ghost user task."""
        self.max_steps = 10
        self.difficulty = (
            TaskDifficulty.HARD if difficulty is None else TaskDifficulty(difficulty)
        )
        self.objective = "Analyze user accounts and identify orphaned/inactive 'ghost' users. Disable only confirmed ghost accounts without affecting active users."

        self._users = []
        self._expected_ghosts = []
        self._identified_ghosts = []
        self._disabled_users = []
        self._total_issues = 0

    def generate_scenario(self) -> Dict[str, Any]:
        """Generate a ghost user scenario."""
        now = datetime.now()

        all_users = [
            {
                "username": "john.doe@company.com",
                "last_login": (now - timedelta(days=5)).isoformat(),
                "created": (now - timedelta(days=365)).isoformat(),
                "active_resources": ["ec2-prod-1", "rds-primary"],
                "recent_deployments": ["v2.1.0", "v2.0.0"],
                "is_ghost": False,
            },
            {
                "username": "jane.smith@company.com",
                "last_login": (now - timedelta(days=120)).isoformat(),
                "created": (now - timedelta(days=500)).isoformat(),
                "active_resources": [],
                "recent_deployments": [],
                "is_ghost": True,
            },
            {
                "username": "bob.wilson@company.com",
                "last_login": (now - timedelta(days=2)).isoformat(),
                "created": (now - timedelta(days=200)).isoformat(),
                "active_resources": ["lambda-processor"],
                "recent_deployments": ["v2.2.0"],
                "is_ghost": False,
            },
            {
                "username": "alice.chen@company.com",
                "last_login": (now - timedelta(days=200)).isoformat(),
                "created": (now - timedelta(days=700)).isoformat(),
                "active_resources": [],
                "recent_deployments": [],
                "is_ghost": True,
            },
            {
                "username": "temp.contractor@company.com",
                "last_login": (now - timedelta(days=95)).isoformat(),
                "created": (now - timedelta(days=100)).isoformat(),
                "active_resources": [],
                "recent_deployments": [],
                "is_ghost": True,
            },
            {
                "username": "service.pipeline@company.com",
                "last_login": (now - timedelta(days=1)).isoformat(),
                "created": (now - timedelta(days=800)).isoformat(),
                "active_resources": ["s3-pipeline-bucket"],
                "recent_deployments": ["v2.2.1"],
                "is_ghost": False,
            },
            {
                "username": "former.employee@company.com",
                "last_login": (now - timedelta(days=450)).isoformat(),
                "created": (now - timedelta(days=900)).isoformat(),
                "active_resources": [],
                "recent_deployments": [],
                "is_ghost": True,
            },
            {
                "username": "mike.johnson@company.com",
                "last_login": (now - timedelta(days=15)).isoformat(),
                "created": (now - timedelta(days=180)).isoformat(),
                "active_resources": ["eks-prod"],
                "recent_deployments": ["v2.1.5"],
                "is_ghost": False,
            },
            {
                "username": "intern.summer2023@company.com",
                "last_login": (now - timedelta(days=300)).isoformat(),
                "created": (now - timedelta(days=400)).isoformat(),
                "active_resources": [],
                "recent_deployments": [],
                "is_ghost": True,
            },
            {
                "username": "devops.automation@company.com",
                "last_login": (now - timedelta(days=3)).isoformat(),
                "created": (now - timedelta(days=1000)).isoformat(),
                "active_resources": ["ecs-cluster", "codedeploy"],
                "recent_deployments": ["v2.3.0", "v2.2.9"],
                "is_ghost": False,
            },
            {
                "username": "legacy.integration@company.com",
                "last_login": (now - timedelta(days=150)).isoformat(),
                "created": (now - timedelta(days=800)).isoformat(),
                "active_resources": [],
                "recent_deployments": [],
                "is_ghost": True,
            },
            {
                "username": "sarah.connor@company.com",
                "last_login": (now - timedelta(days=10)).isoformat(),
                "created": (now - timedelta(days=500)).isoformat(),
                "active_resources": ["s3-bucket"],
                "recent_deployments": ["v2.2.5"],
                "is_ghost": False,
            },
            {
                "username": "project.terminated@company.com",
                "last_login": (now - timedelta(days=500)).isoformat(),
                "created": (now - timedelta(days=1100)).isoformat(),
                "active_resources": [],
                "recent_deployments": [],
                "is_ghost": True,
            },
            {
                "username": "data.science@company.com",
                "last_login": (now - timedelta(days=7)).isoformat(),
                "created": (now - timedelta(days=400)).isoformat(),
                "active_resources": ["sagemaker-endpoint"],
                "recent_deployments": ["ml-pipeline-v3"],
                "is_ghost": False,
            },
            {
                "username": "vacation.replacement@company.com",
                "last_login": (now - timedelta(days=100)).isoformat(),
                "created": (now - timedelta(days=200)).isoformat(),
                "active_resources": [],
                "recent_deployments": [],
                "is_ghost": True,
            },
        ]

        scenario_users = random.sample(all_users, min(8, len(all_users)))

        self._users = scenario_users
        self._expected_ghosts = [u["username"] for u in scenario_users if u["is_ghost"]]
        self._identified_ghosts = []
        self._disabled_users = []
        self._total_issues = len(self._expected_ghosts)

        return {
            "users": scenario_users,
            "ghost_criteria": {
                "no_login_days": 90,
                "no_resources": True,
                "no_recent_deployments": True,
                "created_over_year_ago_unused": True,
            },
            "instructions": "Identify ghost users (inactive >90 days, no resources, no deployments) and disable them.",
        }

    def execute_action(
        self, action: SecOpsAction, grader, task_data: Dict[str, Any]
    ) -> Tuple[float, str, bool, bool]:
        """
        Execute a ghost user action.

        Returns:
            Tuple of (reward, feedback, done, success)
        """
        reward = EPSILON
        feedback = ""
        done = False
        success = False

        if action.action_type == ActionType.ANALYZE:
            feedback = f"Analyzing {len(self._users)} user accounts..."

        elif action.action_type == ActionType.IDENTIFY:
            if action.ghost_users:
                self._identified_ghosts = action.ghost_users
                score = grader.grade_identification(
                    identified=self._identified_ghosts, expected=self._expected_ghosts
                )
                reward = score * 0.4
                feedback = f"Identified {len(self._identified_ghosts)} ghost users. Accuracy: {score:.2f}"
            else:
                feedback = "No ghost users identified."

        elif action.action_type == ActionType.APPLY_FIX:
            if action.disabled_users:
                self._disabled_users = action.disabled_users
                score = grader.grade_disabling(
                    disabled=self._disabled_users,
                    expected_ghosts=self._expected_ghosts,
                    identified_ghosts=self._identified_ghosts,
                )
                reward = score * 0.4
                feedback = (
                    f"Disabled {len(self._disabled_users)} users. Score: {score:.2f}"
                )
            else:
                feedback = "No users disabled."

        elif action.action_type == ActionType.FINALIZE:
            if action.disabled_users:
                self._disabled_users = action.disabled_users

            if not self._disabled_users and action.ghost_users:
                self._disabled_users = action.ghost_users

            score = grader.grade_disabling(
                disabled=self._disabled_users,
                expected_ghosts=self._expected_ghosts,
                identified_ghosts=self._identified_ghosts,
            )
            reward = score

            if score >= 0.9:
                feedback = (
                    f"Excellent! All ghost users properly handled. Score: {score:.2f}"
                )
                success = True
                done = True
            elif score >= 0.5:
                feedback = f"Good work. Some ghost users may remain. Score: {score:.2f}"
            else:
                feedback = f"Ghost users remain active. Score: {score:.2f}"

        else:
            feedback = f"Unknown action type: {action.action_type}"

        return reward, feedback, done, success

    def get_info(self) -> Dict[str, Any]:
        """Get current task information."""
        return {
            "difficulty": self.difficulty,
            "objective": self.objective,
            "detected_issues": self._identified_ghosts,
            "fixed_issues": self._disabled_users,
            "total_issues": self._total_issues,
        }

    def get_state(self) -> Dict[str, Any]:
        """Get current task state."""
        return {
            "total_users": len(self._users),
            "expected_ghosts": len(self._expected_ghosts),
            "identified_ghosts": len(self._identified_ghosts),
            "disabled_users": len(self._disabled_users),
            "remaining_ghosts": len(self._expected_ghosts) - len(self._disabled_users),
        }
