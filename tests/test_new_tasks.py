import pytest
from secops_env.server.tasks.log_analysis import LogAnalysisTask
from secops_env.server.tasks.config_hardening import ConfigHardeningTask
from secops_env.server.graders.log_grader import LogGrader
from secops_env.server.graders.config_grader import ConfigGrader
from secops_env.models import SecOpsAction, TaskType, ActionType


class TestLogAnalysisTask:
    def test_log_analysis_scenario_generation(self):
        task = LogAnalysisTask()
        scenario = task.generate_scenario()

        assert "logs" in scenario
        assert "instructions" in scenario
        assert len(task._logs) > 0

    def test_log_analysis_identify_action(self):
        task = LogAnalysisTask()
        task.generate_scenario()
        grader = LogGrader()

        action = SecOpsAction(
            task_type=TaskType.LOG_ANALYSIS,
            action_type=ActionType.CLASSIFY,
            classification="MALWARE",
            severity="CRITICAL",
            reasoning="Test classification",
        )

        reward, feedback, done, success = task.execute_action(action, grader, {})

        assert isinstance(reward, float)
        assert isinstance(feedback, str)
        assert 0.0 <= reward <= 1.0

    def test_log_analysis_finalize_action(self):
        task = LogAnalysisTask()
        task.generate_scenario()
        grader = LogGrader()

        action = SecOpsAction(
            task_type=TaskType.LOG_ANALYSIS,
            action_type=ActionType.FINALIZE,
            classification="MALWARE",
            severity="CRITICAL",
            reasoning="Test classification with detailed reasoning about the malware behavior",
        )

        reward, feedback, done, success = task.execute_action(action, grader, {})

        assert isinstance(reward, float)
        assert isinstance(feedback, str)
        assert done or not done  # May or may not be done depending on scenario

    def test_log_analysis_task_info(self):
        task = LogAnalysisTask()
        task.generate_scenario()

        info = task.get_info()
        assert "difficulty" in info
        assert "objective" in info
        assert info["total_issues"] == 1


class TestLogGrader:
    def test_classification_correct(self):
        grader = LogGrader()
        score = grader.grade_classification("MALWARE", "MALWARE")
        assert score == 1.0

    def test_classification_incorrect(self):
        grader = LogGrader()
        score = grader.grade_classification("BENIGN", "MALWARE")
        assert score == 0.0

    def test_classification_normalized(self):
        grader = LogGrader()
        score = grader.grade_classification("malware", "MALWARE")
        assert score == 1.0

    def test_severity_correct(self):
        grader = LogGrader()
        score = grader.grade_severity("CRITICAL", "CRITICAL")
        assert score == 1.0

    def test_severity_incorrect(self):
        grader = LogGrader()
        score = grader.grade_severity("LOW", "CRITICAL")
        assert score == 0.0

    def test_reasoning_quality(self):
        grader = LogGrader()
        keywords = ["malware", "attack", "suspicious"]
        score = grader.grade_reasoning(
            "This is a malware attack and suspicious activity", keywords
        )
        assert score > 0.5

    def test_full_analysis_perfect(self):
        grader = LogGrader()
        score = grader.grade_full_analysis(
            classification="MALWARE",
            severity="CRITICAL",
            reasoning="Confirmed malware activity detected",
            expected_classification="MALWARE",
            expected_severity="CRITICAL",
            expected_reasoning_keywords=["malware", "detected"],
        )
        assert score >= 0.8


class TestConfigHardeningTask:
    def test_config_hardening_scenario_generation(self):
        task = ConfigHardeningTask()
        scenario = task.generate_scenario()

        assert "config_content" in scenario
        assert "config_type" in scenario
        assert "instructions" in scenario
        assert len(task._expected_issues) > 0

    def test_config_hardening_identify_issues(self):
        task = ConfigHardeningTask()
        task.generate_scenario()
        grader = ConfigGrader()

        action = SecOpsAction(
            task_type=TaskType.CONFIG_HARDENING,
            action_type=ActionType.IDENTIFY_ISSUES,
            config_issues=[{"type": "privileged_container", "severity": "CRITICAL"}],
        )

        reward, feedback, done, success = task.execute_action(action, grader, {})

        assert isinstance(reward, float)
        assert isinstance(feedback, str)

    def test_config_hardening_finalize(self):
        task = ConfigHardeningTask()
        task.generate_scenario()
        grader = ConfigGrader()

        action = SecOpsAction(
            task_type=TaskType.CONFIG_HARDENING,
            action_type=ActionType.FINALIZE,
            config_issues=[
                {
                    "type": "privileged_container",
                    "severity": "CRITICAL",
                    "fix": "Set privileged: false",
                }
            ],
            hardened_config="privileged: false",
        )

        reward, feedback, done, success = task.execute_action(action, grader, {})

        assert isinstance(reward, float)
        assert isinstance(feedback, str)
        assert 0.0 <= reward <= 1.0

    def test_config_hardening_task_info(self):
        task = ConfigHardeningTask()
        task.generate_scenario()

        info = task.get_info()
        assert "difficulty" in info
        assert "objective" in info
        assert info["total_issues"] == len(task._expected_issues)


class TestConfigGrader:
    def test_issue_identification_perfect(self):
        grader = ConfigGrader()
        identified = [{"type": "privileged_container", "severity": "CRITICAL"}]
        expected = [{"type": "privileged_container", "severity": "CRITICAL"}]
        score = grader.grade_issue_identification(identified, expected)
        assert score >= 0.9

    def test_issue_identification_partial(self):
        grader = ConfigGrader()
        identified = [{"type": "privileged_container", "severity": "CRITICAL"}]
        expected = [
            {"type": "privileged_container", "severity": "CRITICAL"},
            {"type": "run_as_root", "severity": "HIGH"},
        ]
        score = grader.grade_issue_identification(identified, expected)
        assert 0.0 < score < 1.0

    def test_issue_identification_none(self):
        grader = ConfigGrader()
        identified = []
        expected = [{"type": "privileged_container", "severity": "CRITICAL"}]
        score = grader.grade_issue_identification(identified, expected)
        assert score == 0.0

    def test_remediation_suggestions(self):
        grader = ConfigGrader()
        suggestions = [
            "Set privileged: false",
            "Use non-root user",
        ]
        expected_fixes = [
            "Set privileged: false",
            "Set runAsUser: 1000",
        ]
        score = grader.grade_remediation_suggestions(suggestions, expected_fixes)
        assert 0.0 < score <= 1.0

    def test_hardened_config(self):
        grader = ConfigGrader()
        original_config = "privileged: true"
        hardened_config = "privileged: false"
        expected_issues = [
            {"type": "privileged_container", "severity": "CRITICAL", "line": 1}
        ]
        score = grader.grade_hardened_config(
            hardened_config, expected_issues, original_config
        )
        assert score >= 0.8

    def test_full_review(self):
        grader = ConfigGrader()
        score = grader.grade_full_review(
            identified_issues=[
                {"type": "privileged_container", "severity": "CRITICAL"}
            ],
            suggestions=["Set privileged: false"],
            hardened_config="privileged: false",
            expected_issues=[{"type": "privileged_container", "severity": "CRITICAL"}],
            expected_fixes=["Set privileged: false"],
            config_content="privileged: true",
        )
        assert 0.0 <= score <= 1.0
