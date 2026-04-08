"""
Log Grader - Evaluates log analysis task performance.

Scores strictly between 0 and 1 based on:
- Correct classification of log entries
- Correct severity assessment
- Proper reasoning for analysis
"""

from typing import Any, Dict, List, Optional

EPSILON = 1e-9


def _normalize_score(score: float) -> float:
    """Normalize score to be strictly between 0 and 1."""
    if score <= 0:
        return EPSILON
    if score >= 1:
        return 1.0 - EPSILON
    return score


class LogGrader:
    """
    Grader for Log Analysis Task.

    Scoring:
    - Near 1.0: Correct classification, severity, and reasoning
    - 0.5-0.9: Partial completion
    - Near 0.0: Failed to correctly analyze logs
    """

    VALID_CLASSIFICATIONS = {
        "MALWARE",
        "TRUE_POSITIVE",
        "FALSE_POSITIVE",
        "NEEDS_INVESTIGATION",
        "LATERAL_MOVEMENT",
        "DATA_EXFILTRATION",
        "UNAUTHORIZED_ACCESS",
        "BENIGN",
    }

    VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    def grade_classification(
        self, classification: Optional[str], expected_classification: str
    ) -> float:
        """
        Grade the log classification.

        Args:
            classification: Submitted classification
            expected_classification: Expected classification

        Returns:
            Score strictly between 0.0 and 1.0
        """
        if not classification:
            return _normalize_score(EPSILON)

        classification_upper = classification.upper().strip()
        expected_upper = expected_classification.upper().strip()

        if classification_upper == expected_upper:
            return _normalize_score(1.0 - EPSILON)

        classification_normalized = self._normalize_classification(classification_upper)
        expected_normalized = self._normalize_classification(expected_upper)

        if classification_normalized == expected_normalized:
            return _normalize_score(0.9)

        if self._is_related_classification(
            classification_normalized, expected_normalized
        ):
            return _normalize_score(0.5)

        return _normalize_score(EPSILON)

    def grade_severity(self, severity: Optional[str], expected_severity: str) -> float:
        """
        Grade the severity assessment.

        Args:
            severity: Submitted severity
            expected_severity: Expected severity

        Returns:
            Score strictly between 0.0 and 1.0
        """
        if not severity:
            return _normalize_score(EPSILON)

        severity_upper = severity.upper().strip()
        expected_upper = expected_severity.upper().strip()

        if severity_upper == expected_upper:
            return _normalize_score(1.0 - EPSILON)

        severity_level = self._severity_to_level(severity_upper)
        expected_level = self._severity_to_level(expected_upper)

        if severity_level == expected_level:
            return _normalize_score(0.8)

        level_diff = abs(severity_level - expected_level)
        if level_diff == 1:
            return _normalize_score(0.5)
        return _normalize_score(EPSILON)

    def grade_reasoning(
        self, reasoning: Optional[str], expected_reasoning_keywords: List[str]
    ) -> float:
        """
        Grade the reasoning quality.

        Args:
            reasoning: Submitted reasoning text
            expected_reasoning_keywords: Keywords that should appear in reasoning

        Returns:
            Score strictly between 0.0 and 1.0
        """
        if not reasoning:
            return _normalize_score(EPSILON)

        reasoning_lower = reasoning.lower()

        matched_keywords = sum(
            1
            for keyword in expected_reasoning_keywords
            if keyword.lower() in reasoning_lower
        )

        if not expected_reasoning_keywords:
            return _normalize_score(1.0 - EPSILON if len(reasoning) > 10 else 0.5)

        keyword_score = matched_keywords / len(expected_reasoning_keywords)

        length_score = min(1.0, len(reasoning) / 50)

        return _normalize_score((keyword_score * 0.7) + (length_score * 0.3))

    def grade_full_analysis(
        self,
        classification: Optional[str],
        severity: Optional[str],
        reasoning: Optional[str],
        expected_classification: str,
        expected_severity: str,
        expected_reasoning_keywords: List[str],
    ) -> float:
        """
        Grade the complete log analysis.

        Args:
            classification: Submitted classification
            severity: Submitted severity
            reasoning: Submitted reasoning
            expected_classification: Expected classification
            expected_severity: Expected severity
            expected_reasoning_keywords: Keywords for reasoning

        Returns:
            Overall score strictly between 0.0 and 1.0
        """
        class_score = (
            self.grade_classification(classification, expected_classification) * 0.5
        )
        severity_score = self.grade_severity(severity, expected_severity) * 0.25
        reasoning_score = (
            self.grade_reasoning(reasoning, expected_reasoning_keywords) * 0.25
        )

        total_score = class_score + severity_score + reasoning_score

        return _normalize_score(max(0.0, min(1.0, total_score)))

    def grade_alerts(
        self,
        submitted_alerts: Optional[List[Dict[str, Any]]],
        expected_alerts: List[Dict[str, Any]],
    ) -> float:
        """
        Grade a list of analyzed alerts.

        Args:
            submitted_alerts: List of alert analysis results
            expected_alerts: Expected alert analysis results

        Returns:
            Score strictly between 0.0 and 1.0
        """
        if not submitted_alerts:
            return _normalize_score(EPSILON)

        if not expected_alerts:
            return _normalize_score(1.0 - EPSILON if not submitted_alerts else 0.5)

        total_score = 0.0
        matched = 0

        for expected in expected_alerts:
            alert_id = expected.get("alert_id")
            for submitted in submitted_alerts:
                if submitted.get("alert_id") == alert_id:
                    score = self.grade_full_analysis(
                        submitted.get("classification"),
                        submitted.get("severity"),
                        submitted.get("reasoning"),
                        expected.get("expected_classification", ""),
                        expected.get("expected_severity", ""),
                        expected.get("reasoning_keywords", []),
                    )
                    total_score += score
                    matched += 1
                    break

        if matched == 0:
            return _normalize_score(EPSILON)

        avg_score = total_score / len(expected_alerts)

        false_positive_penalty = (
            max(0, len(submitted_alerts) - len(expected_alerts)) * 0.1
        )

        return _normalize_score(max(0.0, min(1.0, avg_score - false_positive_penalty)))

    def _normalize_classification(self, classification: str) -> str:
        """Normalize classification string."""
        classification = classification.replace("-", "_").replace(" ", "_")

        aliases = {
            "TP": "TRUE_POSITIVE",
            "FP": "FALSE_POSITIVE",
            "INVESTIGATION": "NEEDS_INVESTIGATION",
            "INV": "NEEDS_INVESTIGATION",
            "MALICIOUS": "MALWARE",
            "LATERAL": "LATERAL_MOVEMENT",
            "EXFIL": "DATA_EXFILTRATION",
            "UNAUTH": "UNAUTHORIZED_ACCESS",
            "OK": "BENIGN",
            "NORMAL": "BENIGN",
        }

        return aliases.get(classification, classification)

    def _is_related_classification(self, submitted: str, expected: str) -> bool:
        """Check if classifications are related (both malicious, both benign, etc.)."""
        malicious = {
            "MALWARE",
            "TRUE_POSITIVE",
            "LATERAL_MOVEMENT",
            "DATA_EXFILTRATION",
            "UNAUTHORIZED_ACCESS",
        }
        benign = {"FALSE_POSITIVE", "BENIGN"}

        if submitted in malicious and expected in malicious:
            return True
        if submitted in benign and expected in benign:
            return True
        if submitted == "NEEDS_INVESTIGATION" or expected == "NEEDS_INVESTIGATION":
            return True

        return False

    def _severity_to_level(self, severity: str) -> int:
        """Convert severity to numeric level."""
        severity_map = {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }
        return severity_map.get(severity, 0)
