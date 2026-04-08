"""
User Grader - Evaluates ghost user task performance.

Scores strictly between 0 and 1 based on:
- Correct identification of ghost users
- Proper disabling of ghost users
- No false positives (active users not disabled)
"""

from typing import List

EPSILON = 1e-9


def _normalize_score(score: float) -> float:
    """Normalize score to be strictly between 0 and 1."""
    if score <= 0:
        return 0.01
    if score >= 1:
        return 0.99
    return score


class UserGrader:
    """
    Grader for Ghost User Task.

    Scoring:
    - Near 1.0: All ghost users correctly identified and disabled, no false positives
    - 0.5-0.9: Partial completion
    - Near 0.0: Failed to handle ghost users or disabled active users
    """

    def grade_identification(self, identified: List[str], expected: List[str]) -> float:
        """
        Grade the identification of ghost users.

        Args:
            identified: Users identified as ghost accounts
            expected: Actually ghost accounts

        Returns:
            Score strictly between 0.0 and 1.0
        """
        if not expected:
            return _normalize_score(1.0 - EPSILON if not identified else 0.5)

        true_positives = len(set(identified) & set(expected))
        false_positives = len(set(identified) - set(expected))

        precision = true_positives / len(identified) if identified else 0.0
        recall = true_positives / len(expected) if expected else 0.0

        f1 = (
            2 * (precision * recall) / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )

        penalty = false_positives * 0.15
        score = max(0.01, min(0.99, f1 - penalty))

        return _normalize_score(score)

    def grade_disabling(
        self,
        disabled: List[str],
        expected_ghosts: List[str],
        identified_ghosts: List[str],
    ) -> float:
        """
        Grade the disabling of ghost users.

        Args:
            disabled: Users that were disabled
            expected_ghosts: Actually ghost accounts
            identified_ghosts: Accounts identified as ghost

        Returns:
            Score strictly between 0.0 and 1.0
        """
        if not expected_ghosts:
            return _normalize_score(1.0 - EPSILON)

        correctly_disabled = set(disabled) & set(expected_ghosts)
        incorrectly_disabled = set(disabled) - set(expected_ghosts)
        missed_ghosts = set(expected_ghosts) - set(disabled)

        if not missed_ghosts and not incorrectly_disabled:
            return _normalize_score(1.0 - EPSILON)

        true_positives = len(correctly_disabled)

        recall_score = true_positives / len(expected_ghosts) if expected_ghosts else 1.0

        precision_penalty = len(incorrectly_disabled) * 0.25

        score = max(0.01, min(0.99, recall_score - precision_penalty))

        if len(correctly_disabled) == len(expected_ghosts) and not incorrectly_disabled:
            score = 1.0 - EPSILON

        return _normalize_score(score)
