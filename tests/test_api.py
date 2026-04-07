import pytest
from fastapi.testclient import TestClient
from secops_env.server.app import app
from secops_env.models import TaskType, ActionType

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy", "environment": "secops_env"}

def test_environment_reset():
    response = client.post("/reset", json={"task": "pii_redaction"})
    assert response.status_code == 200
    
    data = response.json()
    assert "observation" in data
    assert data["observation"]["task_type"] == "pii_redaction"
    assert data["reward"] == 0.0
    assert data["done"] is False

def test_environment_step():
    # First reset to initialize state
    client.post("/reset", json={"task": "public_access"})
    
    # Then take a step
    action_payload = {
        "action": {
            "task_type": "public_access",
            "action_type": "analyze"
        }
    }
    response = client.post("/step", json=action_payload)
    
    assert response.status_code == 200
    data = response.json()
    assert "observation" in data
    assert "reward" in data
    assert "done" in data