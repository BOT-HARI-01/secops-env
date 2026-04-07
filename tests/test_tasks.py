import pytest
from secops_env.server.tasks.public_access import PublicAccessTask
from secops_env.server.graders.access_grader import AccessGrader
from secops_env.models import SecOpsAction, TaskType, ActionType


def test_public_access_scenario_generation():
    task = PublicAccessTask()
    scenario = task.generate_scenario()

    assert "resources" in scenario
    assert "instructions" in scenario
    assert 4 <= len(task._resources) <= 8  # As defined in min(8, len()) logic


def test_public_access_identify_action():
    task = PublicAccessTask()
    task.generate_scenario()
    grader = AccessGrader()

    # Mock an action where the agent identifies buckets
    action = SecOpsAction(
        task_type=TaskType.PUBLIC_ACCESS,
        action_type=ActionType.IDENTIFY,
        public_resources=["customer-data-backup"],
    )

    reward, feedback, done, success = task.execute_action(action, grader, {})

    assert isinstance(reward, float)
    assert isinstance(feedback, str)
    assert not done  # Shouldn't be done just from identifying
