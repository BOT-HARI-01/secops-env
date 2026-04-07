# Comprehensive Hackathon Plan: SecOps Environment

**Created:** March 28, 2026  
**Goal:** Qualify for Round 2 with maximum score  
**Timeline:** 11 days (until April 8)  
**Mode:** Solo, simulation-based (no AWS/external dependencies)

---

## Executive Summary

This plan transforms `secops_env` from a basic 3-task environment into a polished, impressive submission that demonstrates:

1. **Realistic tool simulation** - Agents execute simulated commands
2. **Diverse security domains** - 5 tasks covering different SecOps scenarios
3. **Sophisticated grading** - F1-based with partial credit and error handling
4. **Production-ready** - HF Space deployment, Docker, comprehensive tests

---

## Constraints

| Constraint | Implication | Solution |
|------------|-------------|----------|
| No AWS account | Can't make real API calls | **Mock command execution** with simulated responses |
| External APIs unavailable | Can't call real services | **All external deps simulated** |
| Testing infrastructure | Hackathon may restrict access | **Self-contained Docker** |
| Solo work | Limited bandwidth | **Prioritize high-impact tasks** |

---

## Phase 0: Preparation (Today - March 28)

### Task 0.1: Environment Setup Checklist
```
□ HF Account ready (for Space deployment)
□ Docker Desktop running
□ Python 3.10+ available
□ Git configured
□ IDE ready (VS Code recommended)
```

### Task 0.2: Repository Structure Review
```
secops_env/
├── __init__.py
├── models.py              # Pydantic models
├── client.py              # HTTP client
├── inference.py           # Baseline script
├── openenv.yaml          # OpenEnv manifest
├── pyproject.toml        # Dependencies
├── Dockerfile
├── README.md
├── server/
│   ├── app.py            # FastAPI server
│   ├── secops_environment.py
│   ├── tasks/
│   │   ├── pii_redaction.py
│   │   ├── public_access.py
│   │   └── ghost_user.py
│   └── graders/
│       ├── pii_grader.py
│       ├── access_grader.py
│       └── user_grader.py
└── tests/
    ├── test_api.py
    ├── test_graders.py
    └── test_tasks.py
```

---

## Phase 1: Core Improvements (Days 1-3)

**Goal:** Establish solid foundation with tool simulation

### Day 1: Tool Simulation Architecture

#### 1.1.1 Create Tool Simulator Module
**File:** `server/tool_simulator.py` (NEW)

```python
class ToolSimulator:
    """Simulates command execution without external dependencies."""
    
    def __init__(self):
        self.execution_log = []
        self.cloud_state = {
            "s3_buckets": {},
            "iam_users": {},
            "ec2_instances": {},
            "security_groups": {}
        }
    
    def execute_aws_command(self, command: str, args: dict) -> dict:
        """
        Parse and execute simulated AWS CLI commands.
        Returns: {"success": bool, "output": str, "error": str | None}
        """
        # Parse command type and execute mock logic
        pass
    
    def get_state(self, resource_type: str, resource_id: str) -> dict:
        """Get current state of a resource."""
        pass
    
    def update_state(self, resource_type: str, resource_id: str, changes: dict):
        """Update simulated resource state."""
        pass
    
    def simulate_delay(self):
        """Add realistic delay to command execution."""
        pass
    
    def generate_audit_log(self) -> list:
        """Return log of all executed commands."""
        pass
```

#### 1.1.2 Update Existing Tasks with Tool Simulation

**PII Redaction Enhancement:**
```
Before: Agent identifies PII → Grader scores → Done
After:  
  1. Agent analyzes text
  2. Agent executes: python /tools/redact.py --input <text>
  3. Simulator runs mock script → Returns redacted output
  4. Agent verifies output
  5. Agent finalizes
  6. Grader scores + execution log checked
```

**Public Access Enhancement:**
```
Before: Agent identifies buckets → Done
After:
  1. Agent analyzes buckets
  2. Agent executes: aws s3api put-public-access-block --bucket <name>
  3. Simulator updates cloud_state
  4. Agent verifies: aws s3api get-public-access-block --bucket <name>
  5. Agent executes for each bucket
  6. Grader scores based on final state + execution log
```

**Ghost User Enhancement:**
```
Before: Agent identifies users → Done
After:
  1. Agent analyzes user accounts
  2. Agent executes: aws iam update-user --user-name <name> --status disabled
  3. Simulator marks user as disabled in cloud_state
  4. Agent verifies with: aws iam get-user --user-name <name>
  5. Grader scores based on disabled users + execution log
```

### Day 2: Add 4th Task - Log Analysis

**File:** `server/tasks/log_analysis.py` (NEW)

#### Task Definition
```
Task: Security Log Triage
Difficulty: Medium
Objective: Analyze firewall/SIEM logs and classify security alerts
```

#### Scenarios Pool (20+ examples)
```python
SCENARIOS = [
    {
        "logs": """
2026-03-28 10:15:23 FIREWALL BLOCK 192.168.1.100 → 8.8.8.8:443 PROTO:TCP
2026-03-28 10:15:24 FIREWALL BLOCK 192.168.1.100 → 45.33.32.156:22 PROTO:TCP
2026-03-28 10:15:25 FIREWALL ALLOW 192.168.1.100 → 10.0.0.5:443 PROTO:TCP
""",
        "classification": "LATERAL_MOVEMENT",
        "severity": "HIGH",
        "reasoning": "Multiple blocked connection attempts to external IPs followed by internal communication"
    },
    # ... 19 more scenarios
]
```

#### Action Types
| Action | Description |
|--------|-------------|
| ANALYZE | Parse and understand log entries |
| CLASSIFY | Assign classification (Malware/True Positive/False Positive/Needs Investigation) |
| PRIORITIZE | Rank alerts by severity |
| FINALIZE | Submit classification report |

#### Grading Criteria
```
Correct classification: +0.4
Correct severity: +0.2
Correct reasoning: +0.2
Partial credit for partial matches
-0.2 per false positive (misclassifying benign as malicious)
```

### Day 3: Add 5th Task - Config Hardening

**File:** `server/tasks/config_hardening.py` (NEW)

#### Task Definition
```
Task: Security Configuration Review
Difficulty: Hard
Objective: Review YAML/JSON configs for security misconfigurations
```

#### Scenarios Pool (15+ examples)
```python
SCENARIOS = [
    {
        "config_type": "yaml",
        "content": """
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  containers:
  - name: app
    image: nginx:latest
    securityContext:
      privileged: true
      runAsUser: 0
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all
spec:
  podSelector: {}
  ingress:
  - {}
""",
        "issues": [
            {"line": 10, "severity": "CRITICAL", "type": "privileged_container"},
            {"line": 11, "severity": "HIGH", "type": "run_as_root"},
            {"line": 19, "severity": "HIGH", "type": "allow_all_policy"}
        ],
        "fixes": [
            "Set privileged: false",
            "Set runAsUser: 1000",
            "Restrict NetworkPolicy to specific pods"
        ]
    },
    # ... 14 more scenarios
]
```

#### Action Types
| Action | Description |
|--------|-------------|
| REVIEW | Analyze configuration file |
| IDENTIFY_ISSUES | Find security problems |
| SUGGEST_FIXES | Propose remediation |
| APPLY_FIXES | Generate hardened config |
| FINALIZE | Submit review report |

---

## Phase 2: Polish & Tests (Days 4-6)

### Day 4: Comprehensive Testing

#### 4.1.1 Add Tests for New Tasks
```python
# tests/test_log_analysis.py
def test_log_analysis_scenario_generation():
    task = LogAnalysisTask()
    scenario = task.generate_scenario()
    assert "logs" in scenario
    assert "classification" in scenario
    assert "severity" in scenario

def test_log_classification():
    task = LogAnalysisTask()
    task.generate_scenario()
    grader = LogGrader()
    
    action = SecOpsAction(
        task_type=TaskType.LOG_ANALYSIS,
        action_type=ActionType.CLASSIFY,
        reasoning="Malicious traffic pattern detected"
    )
    
    reward, feedback, done, success = task.execute_action(action, grader, {})
    assert 0.0 <= reward <= 1.0

# tests/test_config_hardening.py
def test_config_hardening_scenario_generation():
    # Similar structure
    pass

def test_config_issue_identification():
    # Test grading logic
    pass
```

#### 4.1.2 Add Integration Tests
```python
# tests/test_integration.py
def test_full_pii_redaction_workflow():
    """Test agent completes full workflow with tool simulation."""
    # Reset → Analyze → Execute Tool → Verify → Finalize
    pass

def test_full_ghost_user_workflow():
    """Test agent disables ghost users with simulated AWS."""
    # Reset → Analyze → Execute Disable → Verify → Finalize
    pass
```

### Day 5: Documentation & README

#### 5.1.1 Update README Structure
```markdown
# SecOps Environment

## Quick Start
## Architecture
## Tasks
  ### PII Redaction (Easy)
  ### Public Access (Medium)
  ### Ghost User (Hard)
  ### Log Analysis (Medium)
  ### Config Hardening (Hard)
## Tool Simulation
## API Reference
## Development
## Deployment
```

#### 5.1.2 Add Architecture Diagram
```
┌─────────────────────────────────────────────────────────────┐
│                      Client (Agent)                         │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    SecOps Environment                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Tasks     │  │  Tool       │  │     Graders         │  │
│  │             │  │  Simulator  │  │                     │  │
│  │ • PII       │◄─┤             │──►  • PIIGrader       │  │
│  │ • Public    │  │ • AWS Mock  │  │  • AccessGrader     │  │
│  │ • Ghost     │  │ • Shell     │  │  • UserGrader       │  │
│  │ • Log       │  │ • Audit     │  │  • LogGrader        │  │
│  │ • Config    │  │   Log       │  │  • ConfigGrader     │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Day 6: Error Handling & Edge Cases

#### 6.1.1 Add Error Scenarios
```python
# Modify tool simulator to return errors
ERROR_SCENARIOS = [
    {
        "command": "aws s3api put-public-access-block",
        "error": "AccessDenied",
        "simulate_error": True
    },
    {
        "command": "aws iam update-user",
        "error": "NoSuchEntity",
        "simulate_error": True
    }
]

# Tasks should handle errors gracefully
def execute_action(self, action, grader, task_data):
    try:
        result = self.tool_simulator.execute(command)
    except SimulationError as e:
        # Partial credit for correct approach
        return 0.3, f"Command failed: {e}", False, False
```

---

## Phase 3: Deployment & Validation (Days 7-9)

### Day 7: HF Space Deployment

#### 7.1.1 Create HF Space
1. Go to https://huggingface.co/new-space
2. Select Docker template
3. Name: `secops-env` (or your choice)
4. Visibility: Public

#### 7.1.2 Configure Space
```yaml
# README.md header for Space
---
title: SecOps Environment
emoji: 🔒
colorFrom: blue
colorTo: green
sdk: docker
app_port: 8000
---
```

#### 7.1.3 Push to HF
```bash
git init
git add .
git commit -m "Initial SecOps Environment submission"
git remote add origin https://huggingface.co/spaces/<username>/secops-env
git push -u origin main
```

### Day 8: Validation & Testing

#### 8.1.1 Pre-Submission Checklist
```
□ openenv validate passes
□ docker build succeeds
□ docker run works locally
□ HF Space responds to /health
□ HF Space responds to /reset
□ inference.py runs without errors
□ All pytest tests pass
□ No hardcoded credentials
□ README complete
□ License included (BSD-3-Clause)
```

#### 8.1.2 Baseline Run
```bash
HF_TOKEN="your_token" MODEL_NAME="Qwen/Qwen2.5-7B-Instruct" python inference.py
```

Expected output:
```
======================================================================
SECOPS ENVIRONMENT BENCHMARK RESULTS
======================================================================
Task                 Difficulty Avg Reward   Success Rate    Max Reward
----------------------------------------------------------------------
pii_redaction        easy       ~0.70       ~60%           1.000
public_access        medium     ~0.80       ~70%           1.000
ghost_user           hard       ~0.75       ~60%           1.000
log_analysis         medium     ~0.70       ~55%           1.000
config_hardening     hard       ~0.65       ~50%           1.000
----------------------------------------------------------------------
OVERALL                         ~0.72       ~59%
======================================================================
```

### Day 9: Final Polish

- [ ] Clean up any debug output
- [ ] Verify README is comprehensive
- [ ] Check all file headers
- [ ] Update benchmark_results.json with final scores
- [ ] Take screenshots/demo video (optional)

---

## Phase 4: Submission & Buffer (Days 10-11)

### Day 10: Submission
1. Double-check all requirements
2. Submit on hackathon portal
3. Save submission confirmation

### Day 11: Buffer
- Fix any issues discovered
- Prepare backup submission
- Rest

---

## Implementation Details

### New Files to Create

| File | Purpose | Complexity |
|------|---------|------------|
| `server/tool_simulator.py` | Mock AWS CLI execution | Medium |
| `server/tasks/log_analysis.py` | Log triage task | Low |
| `server/tasks/config_hardening.py` | Config review task | Medium |
| `server/graders/log_grader.py` | Log analysis grader | Low |
| `server/graders/config_grader.py` | Config hardening grader | Medium |
| `tests/test_log_analysis.py` | Log task tests | Low |
| `tests/test_config_hardening.py` | Config task tests | Low |
| `tests/test_integration.py` | Integration tests | Medium |

### Files to Modify

| File | Changes | Complexity |
|------|---------|------------|
| `models.py` | Add TaskType.LOG_ANALYSIS, TaskType.CONFIG_HARDENING | Low |
| `secops_environment.py` | Register new tasks | Low |
| `server/app.py` | Update task list | Low |
| `inference.py` | Add prompts for new tasks | Low |
| `openenv.yaml` | Update task definitions | Low |
| `README.md` | Document new tasks | Low |
| `pyproject.toml` | May need updates | Low |

### Estimated Effort

| Component | Hours | Total |
|-----------|-------|-------|
| Tool Simulator | 4-5 | 4-5 |
| Log Analysis Task | 3-4 | 7-9 |
| Config Hardening Task | 4-5 | 11-14 |
| Graders (2) | 2-3 | 13-17 |
| Tests | 3-4 | 16-21 |
| Documentation | 2-3 | 18-24 |
| HF Space Deployment | 2-3 | 20-27 |
| Buffer/Fixes | 3-4 | 23-31 |

**Total estimated: 23-31 hours**

---

## Success Metrics

| Metric | Target | Stretch Goal |
|--------|--------|--------------|
| Tasks implemented | 5 | 5 |
| Test coverage | 80%+ | 90%+ |
| Baseline score | 0.70+ | 0.80+ |
| OpenEnv validate | Pass | Pass with warnings |
| HF Space uptime | 95%+ | 99%+ |
| Documentation | Complete | Comprehensive with examples |

---

## Risk Mitigation

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| HF Space deployment fails | Medium | Test locally first with Docker |
| LLM API rate limits | Medium | Use fallback actions gracefully |
| Time overrun | High | Cut features, not polish |
| Grader bugs | Low | Comprehensive tests |
| Environment issues in testing | Low | Self-contained Docker |

---

## Notes

1. **Start early:** Don't wait until day 10 to deploy
2. **Test incrementally:** Run tests after each feature
3. **Document as you go:** Saves time later
4. **Submit early:** Beat the deadline rush
5. **Keep it simple:** Don't over-engineer

---

*Plan saved for later implementation. Ready to execute when you give the go-ahead.*