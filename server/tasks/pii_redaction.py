"""
PII Redaction Task - Easy Security Task.

Identify and redact Personally Identifiable Information from text.
PII includes: SSN, email addresses, phone numbers, credit card numbers, etc.
"""

import re
from typing import Any, Dict, List, Optional, Tuple
from secops_env.models import SecOpsAction, TaskDifficulty, ActionType


class PIIRedactionTask:
    """
    PII Redaction Task - Easy Difficulty.

    Objective: Identify and redact all personally identifiable information from text.

    Success Criteria:
    - All PII instances correctly identified
    - All PII replaced with [REDACTED]
    - No false positives (non-PII not redacted)

    Reward Structure:
    - +0.1 per correctly identified PII instance
    - +0.5 bonus for 100% completion
    - -0.2 per false positive
    """

    PII_PATTERNS = {
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "phone": r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        "ip_address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    }

    def __init__(self, difficulty: Optional[str] = None):
        """Initialize the PII redaction task."""
        self.max_steps = 5
        self.difficulty = (
            TaskDifficulty.EASY if difficulty is None else TaskDifficulty(difficulty)
        )
        self.objective = "Identify and redact all personally identifiable information (PII) from the text by replacing them with [REDACTED]."

        self._original_text = ""
        self._expected_pii = []
        self._detected_pii = []
        self._redacted_text = ""
        self._total_issues = 0

    def generate_scenario(self) -> Dict[str, Any]:
        """Generate a PII redaction scenario."""
        scenarios = [
            {
                "text": "Customer John Doe (SSN: 123-45-6789) can be reached at john.doe@email.com or 555-123-4567.",
                "expected_pii": [
                    {"type": "ssn", "value": "123-45-6789"},
                    {"type": "email", "value": "john.doe@email.com"},
                    {"type": "phone", "value": "555-123-4567"},
                ],
            },
            {
                "text": "Contact support@company.org for billing issues. Card ending 4532-1234-5678-9010 belongs to Jane Smith.",
                "expected_pii": [
                    {"type": "email", "value": "support@company.org"},
                    {"type": "credit_card", "value": "4532-1234-5678-9010"},
                ],
            },
            {
                "text": "Server at 192.168.1.100 reported issues. Manager: mgr@corp.net, Phone: +1-800-555-0199.",
                "expected_pii": [
                    {"type": "ip_address", "value": "192.168.1.100"},
                    {"type": "email", "value": "mgr@corp.net"},
                    {"type": "phone", "value": "+1-800-555-0199"},
                ],
            },
            {
                "text": "Employee ID: 987-65-4321. Emergency contact: emergency@security.com. Call 555-000-1111 immediately.",
                "expected_pii": [
                    {"type": "ssn", "value": "987-65-4321"},
                    {"type": "email", "value": "emergency@security.com"},
                    {"type": "phone", "value": "555-000-1111"},
                ],
            },
            {
                "text": "Account holder Michael Brown (SSN 456-78-9012) registered with m.brown@personal.io and 800-123-4567.",
                "expected_pii": [
                    {"type": "ssn", "value": "456-78-9012"},
                    {"type": "email", "value": "m.brown@personal.io"},
                    {"type": "phone", "value": "800-123-4567"},
                ],
            },
            {
                "text": "Payment received from visa.card@email.com. Transaction 5678-1234-9876-5432 approved.",
                "expected_pii": [
                    {"type": "email", "value": "visa.card@email.com"},
                    {"type": "credit_card", "value": "5678-1234-9876-5432"},
                ],
            },
            {
                "text": "Database backup stored at 10.0.0.50. Contact admin@backupserver.local for access.",
                "expected_pii": [
                    {"type": "ip_address", "value": "10.0.0.50"},
                    {"type": "email", "value": "admin@backupserver.local"},
                ],
            },
            {
                "text": "Medical records for patient ID 246-80-1357. Contact doctor@hospital.org or 202-555-0188.",
                "expected_pii": [
                    {"type": "ssn", "value": "246-80-1357"},
                    {"type": "email", "value": "doctor@hospital.org"},
                    {"type": "phone", "value": "202-555-0188"},
                ],
            },
            {
                "text": "Network scan detected host at 172.16.0.25. Alert sent to security@network.com.",
                "expected_pii": [
                    {"type": "ip_address", "value": "172.16.0.25"},
                    {"type": "email", "value": "security@network.com"},
                ],
            },
            {
                "text": "Invoice #INV-2024 from billing@client.com. Card: 3782-8224-6310-005 for $1500.",
                "expected_pii": [
                    {"type": "email", "value": "billing@client.com"},
                    {"type": "credit_card", "value": "3782-8224-6310-005"},
                ],
            },
            {
                "text": "User account recovery requested by user123@email.org. Verification ID: 321-78-6549.",
                "expected_pii": [
                    {"type": "email", "value": "user123@email.org"},
                    {"type": "ssn", "value": "321-78-6549"},
                ],
            },
            {
                "text": "API logs show access from 203.0.113.42. Owner: developer@api.io. Phone: 415-555-0199.",
                "expected_pii": [
                    {"type": "ip_address", "value": "203.0.113.42"},
                    {"type": "email", "value": "developer@api.io"},
                    {"type": "phone", "value": "415-555-0199"},
                ],
            },
            {
                "text": "New subscription for Sarah Connor. SSN: 159-26-8743. Email: sarah.c@techmail.com.",
                "expected_pii": [
                    {"type": "ssn", "value": "159-26-8743"},
                    {"type": "email", "value": "sarah.c@techmail.com"},
                ],
            },
            {
                "text": "Server 192.168.50.100 compromised. Admin contact: root@server.net, call 911-555-0101.",
                "expected_pii": [
                    {"type": "ip_address", "value": "192.168.50.100"},
                    {"type": "email", "value": "root@server.net"},
                    {"type": "phone", "value": "911-555-0101"},
                ],
            },
            {
                "text": "Wire transfer to account managed by finance@company.org. Card: 6011-0000-0000-0042.",
                "expected_pii": [
                    {"type": "email", "value": "finance@company.org"},
                    {"type": "credit_card", "value": "6011-0000-0000-0042"},
                ],
            },
            {
                "text": "Customer support ticket from john.smith@customermail.net. Issue ID: 789-45-1236.",
                "expected_pii": [
                    {"type": "email", "value": "john.smith@customermail.net"},
                    {"type": "ssn", "value": "789-45-1236"},
                ],
            },
            {
                "text": "Cloud instance at 54.239.28.85 accessed. Admin: aws-admin@cloud.io. Support: 206-555-0150.",
                "expected_pii": [
                    {"type": "ip_address", "value": "54.239.28.85"},
                    {"type": "email", "value": "aws-admin@cloud.io"},
                    {"type": "phone", "value": "206-555-0150"},
                ],
            },
            {
                "text": "Order confirmation for order@buyer.com. Payment card: 4916-3332-2222-1111 processed.",
                "expected_pii": [
                    {"type": "email", "value": "order@buyer.com"},
                    {"type": "credit_card", "value": "4916-3332-2222-1111"},
                ],
            },
            {
                "text": "Insurance claim from claimant@insurance.net. Policy holder SSN: 654-32-1987. Call 303-555-0177.",
                "expected_pii": [
                    {"type": "email", "value": "claimant@insurance.net"},
                    {"type": "ssn", "value": "654-32-1987"},
                    {"type": "phone", "value": "303-555-0177"},
                ],
            },
            {
                "text": "Database at 10.10.10.50 requires maintenance. DBA: database@corp.com, Phone: 512-555-0111.",
                "expected_pii": [
                    {"type": "ip_address", "value": "10.10.10.50"},
                    {"type": "email", "value": "database@corp.com"},
                    {"type": "phone", "value": "512-555-0111"},
                ],
            },
        ]

        import random

        scenario = random.choice(scenarios)

        self._original_text = scenario["text"]
        self._expected_pii = scenario["expected_pii"]
        self._detected_pii = []
        self._redacted_text = ""
        self._total_issues = len(self._expected_pii)

        return {
            "text": self._original_text,
            "expected_pii": self._expected_pii,
            "instructions": "Replace all PII with [REDACTED]. Return the redacted text.",
        }

    def execute_action(
        self, action: SecOpsAction, grader, task_data: Dict[str, Any]
    ) -> Tuple[float, str, bool, bool]:
        """
        Execute a PII redaction action.

        Returns:
            Tuple of (reward, feedback, done, success)
        """
        reward = 0.0
        feedback = ""
        done = False
        success = False

        if action.action_type == ActionType.ANALYZE:
            feedback = "Analyzing text for PII patterns..."

        elif action.action_type == ActionType.IDENTIFY:
            self._detected_pii = (
                action.redacted_text.split(",") if action.redacted_text else []
            )
            feedback = f"Identified {len(self._detected_pii)} potential PII items."
            reward = len(self._detected_pii) * 0.05

        elif action.action_type == ActionType.FINALIZE:
            if action.redacted_text:
                self._redacted_text = action.redacted_text
                score = grader.grade_redaction(
                    original_text=self._original_text,
                    redacted_text=action.redacted_text,
                    expected_pii=self._expected_pii,
                )
                reward = score

                if score >= 0.9:
                    feedback = (
                        f"Excellent! Score: {score:.2f}. All PII correctly redacted."
                    )
                    success = True
                    done = True
                elif score >= 0.5:
                    feedback = f"Good attempt. Score: {score:.2f}. Some PII may have been missed."
                else:
                    feedback = f"Incomplete redaction. Score: {score:.2f}. Review and try again."
            else:
                feedback = "No redacted text provided."
                reward = -0.1

        else:
            feedback = f"Unknown action type: {action.action_type}"

        return reward, feedback, done, success

    def get_info(self) -> Dict[str, Any]:
        """Get current task information."""
        return {
            "difficulty": self.difficulty,
            "objective": self.objective,
            "detected_issues": [p["value"] for p in self._detected_pii],
            "fixed_issues": [],
            "total_issues": self._total_issues,
        }

    def get_state(self) -> Dict[str, Any]:
        """Get current task state."""
        return {
            "original_text": self._original_text,
            "expected_pii_count": len(self._expected_pii),
            "detected_count": len(self._detected_pii),
            "has_redacted_text": bool(self._redacted_text),
        }
