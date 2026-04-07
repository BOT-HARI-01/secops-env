import pytest
from secops_env.server.graders.pii_grader import PIIGrader


def test_pii_grader_perfect_score():
    grader = PIIGrader()
    original_text = "My SSN is 123-45-6789"
    redacted_text = "My SSN is [REDACTED]"
    expected_pii = [{"type": "ssn", "value": "123-45-6789"}]

    score = grader.grade_redaction(original_text, redacted_text, expected_pii)
    assert score == 1.0


def test_pii_grader_partial_score():
    grader = PIIGrader()
    original_text = "Contact 123-45-6789 or test@email.com"
    # Only redacted the email, missed the SSN
    redacted_text = "Contact 123-45-6789 or [REDACTED]"
    expected_pii = [
        {"type": "ssn", "value": "123-45-6789"},
        {"type": "email", "value": "test@email.com"},
    ]

    score = grader.grade_redaction(original_text, redacted_text, expected_pii)
    assert 0.0 < score < 1.0  # Should be partial credit


def test_pii_grader_no_pii_clean():
    grader = PIIGrader()
    original_text = "My ID is 999"
    redacted_text = "My ID is 999"  # No PII to redact
    expected_pii = []  # No PII expected

    score = grader.grade_redaction(original_text, redacted_text, expected_pii)
    assert score == 1.0  # Clean pass when no PII exists


def test_pii_grader_exposed_pii():
    grader = PIIGrader()
    original_text = "No PII here"
    redacted_text = "SSN: 123-45-6789"  # PII somehow exposed
    expected_pii = []  # No PII expected

    score = grader.grade_redaction(original_text, redacted_text, expected_pii)
    assert score == 0.0  # Failed because PII was exposed
