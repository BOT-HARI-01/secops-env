"""
Config Grader - Evaluates configuration hardening task performance.

Scores 0.0 to 1.0 based on:
- Correct identification of security issues
- Appropriate severity assessment
- Proper remediation suggestions
- Correct configuration fixes
"""

from typing import Any, Dict, List, Optional, Set, Tuple


class ConfigGrader:
    """
    Grader for Config Hardening Task.

    Scoring:
    - 1.0: All issues identified with correct severity, proper fixes applied
    - 0.5-0.9: Partial completion
    - 0.0: Failed to identify or fix issues
    """

    SEVERITY_LEVELS = {
        "INFO": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    ISSUE_TYPE_PATTERNS = {
        "privileged_container": ["privileged", "root", "elevated"],
        "run_as_root": ["runasuser", "runasuser=0", "root", "uid 0"],
        "allow_all_policy": ["allow-all", "allow_all", "from: {}", "podSelector: {}"],
        "insecure_port": ["port: 80", "port: 8080", "port: 23"],
        "plaintext_secret": ["password:", "secret:", "api-key"],
        "missing_tls": ["tls: false", "tls: false"],
        "overpermissive_iam": ["*: *", "Action: *", "Resource: *"],
        "public_s3": ["PublicAccessBlockConfiguration"],
        "weak_encryption": ["aes-128", "md5", "sha1"],
        "missing_firewall": ["0.0.0.0/0", "::/0"],
    }

    def grade_issue_identification(
        self,
        identified_issues: Optional[List[Dict[str, Any]]],
        expected_issues: List[Dict[str, Any]],
    ) -> float:
        """
        Grade the identification of configuration issues.

        Args:
            identified_issues: List of issues identified by the agent
            expected_issues: List of expected issues in the config

        Returns:
            Score between 0.0 and 1.0
        """
        if not expected_issues:
            return 1.0 if not identified_issues else 0.5

        if not identified_issues:
            return 0.0

        true_positives = 0
        false_positives = 0

        matched_expected: Set[int] = set()

        for identified in identified_issues:
            identified_type = identified.get("type", "").lower()
            identified_severity = identified.get("severity", "MEDIUM").upper()

            matched = False
            for i, expected in enumerate(expected_issues):
                if i in matched_expected:
                    continue

                expected_type = expected.get("type", "").lower()
                expected_severity = expected.get("severity", "MEDIUM").upper()

                if self._types_match(identified_type, expected_type):
                    matched_expected.add(i)
                    true_positives += 1
                    matched = True

                    severity_bonus = self._severity_match_bonus(
                        identified_severity, expected_severity
                    )
                    true_positives += severity_bonus * 0.1
                    break

            if not matched:
                false_positives += 1

        recall = true_positives / len(expected_issues) if expected_issues else 0.0

        precision_penalty = false_positives * 0.15

        f1_based_score = (
            2
            * (true_positives / len(expected_issues))
            * recall
            / (true_positives / len(expected_issues) + recall + 0.001)
        )

        score = max(0.0, min(1.0, f1_based_score - precision_penalty))

        return score

    def grade_remediation_suggestions(
        self,
        suggestions: Optional[List[str]],
        expected_fixes: List[str],
    ) -> float:
        """
        Grade the remediation suggestions.

        Args:
            suggestions: List of suggested fixes
            expected_fixes: List of expected fixes

        Returns:
            Score between 0.0 and 1.0
        """
        if not expected_fixes:
            return 1.0

        if not suggestions:
            return 0.0

        matched = 0
        for suggestion in suggestions:
            suggestion_lower = suggestion.lower()
            for expected in expected_fixes:
                expected_lower = expected.lower()
                if any(
                    keyword in suggestion_lower for keyword in expected_lower.split()
                ):
                    matched += 1
                    break

        coverage = matched / len(expected_fixes) if expected_fixes else 0.0

        precision = matched / len(suggestions) if suggestions else 0.0

        if coverage > 0 and precision > 0:
            f1 = 2 * (precision * coverage) / (precision + coverage)
        else:
            f1 = 0.0

        return max(0.0, min(1.0, f1))

    def grade_hardened_config(
        self,
        hardened_config: Optional[str],
        expected_issues: List[Dict[str, Any]],
        config_content: str,
    ) -> float:
        """
        Grade the hardened configuration output.

        Args:
            hardened_config: The fixed configuration
            expected_issues: Issues that should be fixed
            config_content: Original configuration content

        Returns:
            Score between 0.0 and 1.0
        """
        if not hardened_config:
            return 0.0

        if not expected_issues:
            return 1.0

        fixed_count = 0
        for issue in expected_issues:
            issue_type = issue.get("type", "").lower()
            line = issue.get("line")

            if self._issue_fixed_in_config(
                hardened_config, issue_type, line, config_content
            ):
                fixed_count += 1

        severity_weights = {
            "CRITICAL": 1.5,
            "HIGH": 1.2,
            "MEDIUM": 1.0,
            "LOW": 0.8,
            "INFO": 0.5,
        }

        weighted_fixed = 0.0
        total_weight = 0.0
        for issue in expected_issues:
            severity = issue.get("severity", "MEDIUM").upper()
            weight = severity_weights.get(severity, 1.0)
            total_weight += weight

            if self._issue_fixed_in_config(
                hardened_config,
                issue.get("type", "").lower(),
                issue.get("line"),
                config_content,
            ):
                weighted_fixed += weight

        if total_weight == 0:
            return 1.0

        return max(0.0, min(1.0, weighted_fixed / total_weight))

    def grade_full_review(
        self,
        identified_issues: Optional[List[Dict[str, Any]]],
        suggestions: Optional[List[str]],
        hardened_config: Optional[str],
        expected_issues: List[Dict[str, Any]],
        expected_fixes: List[str],
        config_content: str,
    ) -> float:
        """
        Grade the complete configuration review.

        Args:
            identified_issues: Issues identified
            suggestions: Remediation suggestions
            hardened_config: Fixed configuration
            expected_issues: Expected issues
            expected_fixes: Expected fixes
            config_content: Original config

        Returns:
            Overall score between 0.0 and 1.0
        """
        identification_score = (
            self.grade_issue_identification(identified_issues, expected_issues) * 0.4
        )
        suggestion_score = (
            self.grade_remediation_suggestions(suggestions, expected_fixes) * 0.3
        )
        fix_score = (
            self.grade_hardened_config(hardened_config, expected_issues, config_content)
            * 0.3
        )

        total_score = identification_score + suggestion_score + fix_score

        return max(0.0, min(1.0, total_score))

    def _types_match(self, identified_type: str, expected_type: str) -> bool:
        """Check if issue types match."""
        if identified_type == expected_type:
            return True

        identified_lower = identified_type.lower()
        expected_lower = expected_type.lower()

        for pattern_type, keywords in self.ISSUE_TYPE_PATTERNS.items():
            if expected_lower == pattern_type or expected_lower in pattern_type:
                if any(kw in identified_lower for kw in keywords):
                    return True
            if identified_lower == pattern_type or identified_lower in pattern_type:
                if any(kw in expected_lower for kw in keywords):
                    return True

        return False

    def _severity_match_bonus(self, identified: str, expected: str) -> float:
        """Calculate bonus for severity match."""
        if identified == expected:
            return 0.5

        identified_level = self.SEVERITY_LEVELS.get(identified.upper(), 0)
        expected_level = self.SEVERITY_LEVELS.get(expected.upper(), 0)

        if identified_level == expected_level:
            return 0.3

        level_diff = abs(identified_level - expected_level)
        if level_diff == 1:
            return 0.1

        return 0.0

    def _issue_fixed_in_config(
        self,
        hardened_config: str,
        issue_type: str,
        line: Optional[int],
        original_config: str,
    ) -> bool:
        """Check if an issue is fixed in the hardened config."""
        issue_lower = issue_type.lower()

        if "privileged" in issue_lower:
            return (
                "privileged: false" in hardened_config.lower()
                or "privileged:false" in hardened_config.lower()
            )
        elif "run_as_root" in issue_lower or "runasuser" in issue_lower:
            return "runAsNonRoot: true" in hardened_config.lower() or (
                "runAsUser" in hardened_config and "1000" in hardened_config
            )
        elif "allow_all" in issue_lower:
            return not (
                "podSelector: {}" in hardened_config and "ingress:" in hardened_config
            )
        elif "public" in issue_lower:
            return "blockpublicaccess" in hardened_config.lower()
        elif "insecure" in issue_lower or "port: 80" in issue_lower:
            return "443" in hardened_config or "tls" in hardened_config.lower()

        return True
