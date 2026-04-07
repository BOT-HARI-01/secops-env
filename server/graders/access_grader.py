"""
Access Grader - Evaluates public access task performance.

Scores 0.0 to 1.0 based on:
- Correct identification of public resources
- Proper fixing of public access
- No false positives
"""

from typing import List


class AccessGrader:
    """
    Grader for Public Access Task.

    Scoring:
    - 1.0: All public resources identified and fixed, no false positives
    - 0.5-0.9: Partial completion
    - 0.0: Failed to identify/fix public resources
    """

    def grade_identification(self, identified: List[str], expected: List[str]) -> float:
        """
        Grade the identification of public resources.

        Args:
            identified: Resources identified as public
            expected: Actually public resources

        Returns:
            Score between 0.0 and 1.0
        """
        if not expected:
            return 1.0 if not identified else 0.5

        true_positives = len(set(identified) & set(expected))
        false_positives = len(set(identified) - set(expected))
        false_negatives = len(set(expected) - set(identified))

        precision = true_positives / len(identified) if identified else 0.0
        recall = true_positives / len(expected) if expected else 0.0

        f1 = (
            2 * (precision * recall) / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )

        penalty = false_positives * 0.1
        score = max(0.0, min(1.0, f1 - penalty))

        return score

    def grade_fix(
        self, fixed: List[str], expected_public: List[str], identified: List[str]
    ) -> float:
        """
        Grade the fixing of public access.

        Args:
            fixed: Resources that were fixed (made private)
            expected_public: Actually public resources
            identified: Resources identified as public

        Returns:
            Score between 0.0 and 1.0
        """
        if not expected_public:
            return 1.0

        correctly_fixed = set(fixed) & set(expected_public)
        missed_public = set(expected_public) - set(fixed)
        incorrectly_fixed = set(fixed) - set(expected_public)

        if not missed_public and not incorrectly_fixed:
            return 1.0

        if not fixed:
            return 0.0

        true_positives = len(correctly_fixed)
        false_positives = len(incorrectly_fixed)

        base_score = true_positives / len(expected_public) if expected_public else 1.0
        penalty = false_positives * 0.2

        score = max(0.0, min(1.0, base_score - penalty))

        if len(correctly_fixed) == len(expected_public) and not incorrectly_fixed:
            score = 1.0

        return score
