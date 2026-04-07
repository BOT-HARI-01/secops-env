---
title: SecOps Environment
emoji: 🔐
colorFrom: purple
colorTo: blue
sdk: docker
app_port: 8000
pinned: false
license: bsd-3-clause
---
# SecOps Environment - OpenEnv

**Security Operations Environment for AI Agent Training and Evaluation**

[![OpenEnv Compatible](https://img.shields.io/badge/OpenEnv-0.2.0+-blue.svg)](https://github.com/meta-pytorch/OpenEnv)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-green.svg)](https://www.python.org/)

---

## Overview

**SecOps Environment** is a real-world security operations environment built on the OpenEnv framework. It simulates common DevOps/SecOps tasks that security analysts perform daily, providing a standardized benchmark for evaluating AI agents in security operations.

### Why SecOps?

Security operations is a critical domain with:
- **High-stakes decisions**: Misclassified security issues can lead to data breaches
- **Deterministic success states**: Unlike open-ended tasks, security fixes can be verified programmatically
- **Real-world applicability**: Training agents on actual security tasks has immediate practical value
- **Clear evaluation metrics**: Success can be measured precisely (PII removed, buckets fixed, users disabled)

---

## Tasks

### 1. PII Redaction (Easy)

**Objective**: Identify and redact Personally Identifiable Information from text.

**PII Types Detected**:
- Social Security Numbers (SSN: XXX-XX-XXXX)
- Email addresses (user@domain.com)
- Phone numbers (XXX-XXX-XXXX)
- Credit card numbers (XXXX-XXXX-XXXX-XXXX)
- IP addresses (XXX.XXX.XXX.XXX)

**Success Criteria**: All PII replaced with `[REDACTED]`, no false positives

**Reward Structure**:
- +0.1 per correctly identified PII
- +0.5 bonus for 100% completion
- -0.2 per false positive

---

### 2. Fix Public Access (Medium)

**Objective**: Identify S3 buckets with public access and fix their permissions.

**Task**: Analyze cloud storage resources and identify buckets with overly permissive access policies.

**Success Criteria**: All public buckets identified and fixed to block public access

**Reward Structure**:
- +0.15 per correctly identified public resource
- +0.4 bonus for fixing all public resources
- -0.1 per missed public resource
- -0.2 per false positive

---

### 3. Disable Ghost User (Hard)

**Objective**: Identify orphaned/inactive user accounts and disable them.

**Ghost User Criteria**:
- No login in 90+ days
- No active cloud resources
- No recent deployments
- Created >1 year ago and never active

**Success Criteria**: All ghost users correctly identified and disabled, no active users disabled

**Reward Structure**:
- +0.1 per correctly identified ghost user
- +0.3 bonus for correctly disabling all
- -0.2 per incorrect disable (active user marked as ghost)

---

### 4. Log Analysis (Medium)

**Objective**: Analyze security logs and classify security events with appropriate severity.

**Classifications**:
- `MALWARE`: Confirmed malware activity
- `TRUE_POSITIVE`: Confirmed security threat
- `FALSE_POSITIVE`: Benign event misidentified as threat
- `NEEDS_INVESTIGATION`: Uncertain, requires further analysis
- `LATERAL_MOVEMENT`: Attacker moving through network
- `DATA_EXFILTRATION`: Unauthorized data transfer
- `UNAUTHORIZED_ACCESS`: Access without proper credentials
- `BENIGN`: Normal, safe activity

**Severity Levels**: LOW, MEDIUM, HIGH, CRITICAL

**Success Criteria**: Correct classification, accurate severity, clear reasoning

**Reward Structure**:
- +0.5 for correct classification
- +0.25 for correct severity
- +0.25 for adequate reasoning

---

### 5. Configuration Hardening (Hard)

**Objective**: Review YAML/JSON configurations for security misconfigurations.

**Common Issues Detected**:
- Privileged containers (privileged: true)
- Running as root (runAsUser: 0)
- Overly permissive IAM policies
- Plaintext secrets in config
- Public S3 bucket access
- Missing TLS/SSL configuration
- Overly permissive network policies
- Exposed services (LoadBalancer, hostPort)

**Success Criteria**: All security issues identified with correct severity, proper fixes applied

**Reward Structure**:
- +0.4 for correct issue identification
- +0.3 for appropriate remediation
- +0.3 for correct configuration fixes

---

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/secops_env.git
cd secops_env

# Install dependencies
pip install -e .

# Or with uv
uv pip install -e .
```

### Running the Server

```bash
# Using the installed script
secops-env-server

# Or directly
python -m secops_env.server.app
```

### Using the Environment

```python
from secops_env import SecOpsEnv, SecOpsAction
from secops_env.models import TaskType, ActionType

# Sync usage (recommended for simple scripts)
with SecOpsEnv(base_url="http://localhost:8000").sync() as env:
    # Reset for PII redaction task
    result = env.reset(task="pii_redaction")
    print(f"Objective: {result.observation.objective}")
    print(f"Text to redact: {result.observation.context.get('text')}")
    
    # Execute actions
    action = SecOpsAction(
        task_type=TaskType.PII_REDACTION,
        action_type=ActionType.FINALIZE,
        redacted_text="Customer [REDACTED]..."
    )
    result = env.step(action)
    print(f"Reward: {result.reward}")
    print(f"Done: {result.done}")

# Async usage
import asyncio

async def main():
    async with SecOpsEnv(base_url="http://localhost:8000") as env:
        result = await env.reset(task="public_access")
        # ... interact with environment
        
asyncio.run(main())
```

### Running Baseline Inference

```bash
# Set environment variables
export API_BASE_URL="https://router.huggingface.co/v1"
export MODEL_NAME="Qwen/Qwen2.5-7B-Instruct"  # Default model
export HF_TOKEN="your_token_here"

# Run baseline evaluation
python inference.py
```

---

## Environment API

### `reset(task=None, difficulty=None, seed=None)`

Reset the environment for a new episode.

**Parameters**:
- `task` (str, optional): Task type ("pii_redaction", "public_access", "ghost_user")
- `difficulty` (str, optional): Difficulty level ("easy", "medium", "hard")
- `seed` (int, optional): Random seed for reproducibility

**Returns**: `StepResult` with initial observation

### `step(action)`

Execute an action in the environment.

**Parameters**:
- `action` (SecOpsAction): Action to execute

**Returns**: `StepResult` with observation, reward, and done flag

### `state()`

Get current environment state.

**Returns**: Dictionary with episode metadata

---

## Action Space

```python
class SecOpsAction(BaseModel):
    task_type: TaskType                    # Current task
    action_type: ActionType                # Type of action
    
    # PII Redaction
    redacted_text: Optional[str] = None
    
    # Public Access
    public_resources: Optional[List[str]] = None
    fixed_resources: Optional[List[str]] = None
    
    # Ghost User
    ghost_users: Optional[List[str]] = None
    disabled_users: Optional[List[str]] = None
    
    confidence: Optional[float] = None
    reasoning: Optional[str] = None
```

## Observation Space

```python
class SecOpsObservation(BaseModel):
    task_type: TaskType
    task_difficulty: TaskDifficulty
    objective: str                         # Clear objective
    
    context: Dict[str, Any]                # Scenario data
    available_actions: List[str]
    current_state: Dict[str, Any]
    
    partial_progress: float                # 0.0-1.0
    step_count: int
    max_steps: int
    
    feedback: Optional[str] = None
    detected_issues: List[str] = []
    fixed_issues: List[str] = []
    
    reward_accumulated: float
    done: bool
    success: bool
```

---

## Project Structure

```
secops_env/
├── __init__.py                 # Package exports
├── models.py                   # Pydantic models
├── client.py                   # EnvClient implementation
├── openenv.yaml               # Environment manifest
├── pyproject.toml             # Dependencies
├── Dockerfile                 # Container build
├── inference.py              # Baseline inference script
├── README.md                  # This file
└── server/
    ├── __init__.py
    ├── app.py                 # FastAPI application
    ├── secops_environment.py  # Core environment logic
    ├── tool_simulator.py     # Mock AWS CLI execution
    ├── tasks/
    │   ├── pii_redaction.py   # Easy task
    │   ├── public_access.py   # Medium task
    │   ├── ghost_user.py      # Hard task
    │   ├── log_analysis.py    # Medium task
    │   └── config_hardening.py # Hard task
    └── graders/
        ├── pii_grader.py
        ├── access_grader.py
        ├── user_grader.py
        ├── log_grader.py
        └── config_grader.py
```

---

## Baseline Scores

Expected baseline performance on Qwen/Qwen2.5-7B-Instruct:

| Task | Difficulty | Avg Reward | Success Rate |
|------|------------|-----------|--------------|
| PII Redaction | Easy | ~0.70 | ~60% |
| Fix Public Access | Medium | ~0.80 | ~70% |
| Disable Ghost User | Hard | ~0.75 | ~60% |
| Log Analysis | Medium | ~0.70 | ~55% |
| Config Hardening | Hard | ~0.65 | ~50% |
| **Overall** | - | ~0.72 | ~59% |

*Note: Actual scores may vary based on model capabilities and prompting strategies.*

---

## Docker Deployment

### Building the Image

```bash
docker build -t secops-env:latest .
```

### Running the Container

```bash
docker run -p 8000:8000 secops-env:latest
```

### Deploying to Hugging Face Spaces

```bash
# Install OpenEnv CLI
pip install openenv-cli

# Login to Hugging Face
huggingface-cli login

# Push to Spaces
openenv push --repo-id yourusername/secops-env
```

---

## Development

### Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v
```

### Testing Individual Tasks

```bash
# Test PII Redaction
python -c "
from secops_env.server.tasks.pii_redaction import PIIRedactionTask
from secops_env.server.graders.pii_grader import PIIGrader

task = PIIRedactionTask()
data = task.generate_scenario()
print('Scenario:', data)
"
```

---

## API Reference

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `API_BASE_URL` | LLM API endpoint | `https://router.huggingface.co/v1` |
| `MODEL_NAME` | Model identifier | Required |
| `HF_TOKEN` | API key | Required |
| `MAX_STEPS` | Max steps per episode | `10` |
| `TEMPERATURE` | Model temperature | `0.2` |

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

---

## License

BSD 3-Clause License - see LICENSE file for details.

---

## Acknowledgments

- Built on [OpenEnv](https://github.com/meta-pytorch/OpenEnv) framework
- Inspired by real-world security operations workflows
- Developed for AI safety and agent evaluation research
