"""
PII Grader - Evaluates PII redaction task performance.

Scores strictly between 0 and 1 based on:
- Correct identification of PII
- Proper redaction (no PII in output)
- No false positives
"""

import re
from typing import List, Dict, Any

EPSILON = 1e-9


def _normalize_score(score: float) -> float:
    """Normalize score to be strictly between 0 and 1."""
    if score <= 0:
        return EPSILON
    if score >= 1:
        return 1.0 - EPSILON
    return score


class PIIGrader:
    """
    Grader for PII Redaction Task.

    Scoring:
    - Near 1.0: All PII correctly redacted, no false positives
    - 0.5-0.9: Partial completion
    - Near 0.0: Failed to redact PII
    """

    PII_PATTERNS = {
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "phone": r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        "ip_address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    }

    def grade_redaction(
        self, original_text: str, redacted_text: str, expected_pii: List[Dict[str, Any]]
    ) -> float:
        """
        Grade the PII redaction result.

        Args:
            original_text: The original text with PII
            redacted_text: The text after redaction attempts
            expected_pii: List of expected PII items [{"type": "...", "value": "..."}]

        Returns:
            Score strictly between 0.0 and 1.0
        """
        if not expected_pii:
            return _normalize_score(
                1.0 if not self._contains_pii(redacted_text) else EPSILON
            )

        correctly_redacted = 0
        false_positives = self._count_exposed_pii(redacted_text)

        for pii_item in expected_pii:
            pii_value = pii_item["value"]
            if pii_value not in redacted_text:
                correctly_redacted += 1

        total_expected = len(expected_pii)

        recall = correctly_redacted / total_expected if total_expected > 0 else 1.0

        precision = 1.0 - min(0.99, false_positives * 0.2)

        base_score = (precision + recall) / 2

        if correctly_redacted == total_expected and false_positives == 0:
            base_score = 1.0 - EPSILON

        return _normalize_score(base_score)

    def _contains_pii(self, text: str) -> bool:
        """Check if text contains any PII."""
        for pattern in self.PII_PATTERNS.values():
            if re.search(pattern, text):
                return True
        return False

    def _count_exposed_pii(self, text: str) -> int:
        """Count the number of exposed PII items."""
        count = 0
        for pattern in self.PII_PATTERNS.values():
            matches = re.findall(pattern, text)
            count += len(matches)
        return count
