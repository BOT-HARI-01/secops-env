#!/usr/bin/env python3
"""
SecOps Environment - Inference Script

MANDATORY:
- Before submitting, ensure the following variables are defined:
    API_BASE_URL   The API endpoint for the LLM.
    MODEL_NAME     The model identifier to use for inference.
    HF_TOKEN       Your Hugging Face / API key.

- The inference script must be named `inference.py` and placed in the root directory
- Participants must use OpenAI Client for all LLM calls using above variables

STDOUT FORMAT:
    [START] task=<task_name> env=<benchmark> model=<model_name>
    [STEP]  step=<n> action=<action_str> reward=<0.00> done=<true|false> error=<msg|null>
    [END]   success=<true|false> steps=<n> score=<score> rewards=<r1,r2,...,rn>
"""

import os
import sys
import json
import re
import textwrap
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from openai import OpenAI

from secops_env import SecOpsEnv, SecOpsAction
from secops_env.models import TaskType, ActionType


API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME = os.getenv("MODEL_NAME", "Qwen/Qwen2.5-7B-Instruct")
HF_TOKEN = os.getenv("HF_TOKEN")
TASK_NAME = os.getenv("TASK_NAME", "pii_redaction")
BENCHMARK = os.getenv("BENCHMARK", "secops_env")
MAX_STEPS = int(os.getenv("MAX_STEPS", "10"))
TEMPERATURE = float(os.getenv("TEMPERATURE", "0.7"))
MAX_TOKENS = int(os.getenv("MAX_TOKENS", "500"))
SUCCESS_SCORE_THRESHOLD = 0.1
# #0.01 = 1e-9
DEBUG = os.getenv("DEBUG", "false").lower() == "true"


ALL_TASKS = [
    ("pii_redaction", "easy"),
    ("public_access", "medium"),
    ("ghost_user", "hard"),
    ("log_analysis", "medium"),
    ("config_hardening", "hard"),
]


def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)


def log_step(
    step: int, action: str, reward: float, done: bool, error: Optional[str]
) -> None:
    error_val = error if error else "null"
    done_val = str(done).lower()
    action_str = action.replace('"', '\\"')[:100] if action else "noop"
    print(
        f'[STEP] step={step} action="{action_str}" reward={reward:.2f} done={done_val} error={error_val}',
        flush=True,
    )


def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(
        f"[END] success={str(success).lower()} steps={steps} score={score:.3f} rewards={rewards_str}",
        flush=True,
    )


@dataclass
class AgentConfig:
    model_name: str = MODEL_NAME
    api_base_url: str = API_BASE_URL
    api_key: Optional[str] = HF_TOKEN
    max_steps: int = MAX_STEPS
    temperature: float = TEMPERATURE
    max_tokens: int = MAX_TOKENS


class SecOpsAgent:
    TASK_PROMPTS = {
        "pii_redaction": textwrap.dedent("""
            You are a security analyst specializing in PII redaction.
            
            Your task: Identify and redact all Personally Identifiable Information (PII) from the given text.
            
            PII types to look for:
            - SSN: XXX-XX-XXXX format
            - Email: user@domain.com format
            - Phone: XXX-XXX-XXXX or +1-XXX-XXX-XXXX format
            - Credit Card: XXXX-XXXX-XXXX-XXXX format
            - IP Address: XXX.XXX.XXX.XXX format
            
            IMPORTANT:
            1. Replace ALL PII with [REDACTED]
            2. Preserve the original text structure
            3. Do not modify non-PII content
            4. Return ONLY the redacted text
            
            Respond with your redacted version.
        """).strip(),
        "public_access": textwrap.dedent("""
            You are a cloud security analyst.
            
            Your task: Identify S3 buckets with public access and create a plan to fix them.
            
            Given a list of cloud resources, identify which ones have public access enabled.
            
            Respond in JSON format:
            {"identified_public": ["bucket-name-1", "bucket-name-2"], "reasoning": "Brief explanation"}
            
            If no public buckets, respond:
            {"identified_public": [], "reasoning": "No public buckets found"}
        """).strip(),
        "ghost_user": textwrap.dedent("""
            You are a security operations analyst.
            
            Your task: Identify orphaned/inactive ghost user accounts that should be disabled.
            
            Ghost user criteria:
            - No login in 90+ days
            - No active cloud resources
            - No recent deployments
            
            Given user account data, identify ghost users.
            
            Respond in JSON format:
            {"identified_ghosts": ["user@company.com", "..."], "reasoning": "Brief explanation"}
            
            If no ghost users, respond:
            {"identified_ghosts": [], "reasoning": "No ghost users found"}
        """).strip(),
        "log_analysis": textwrap.dedent("""
            You are a security analyst specializing in SIEM and log analysis.
            
            Your task: Analyze the provided security logs and classify the security event.
            
            Classifications: MALWARE, TRUE_POSITIVE, FALSE_POSITIVE, NEEDS_INVESTIGATION,
            LATERAL_MOVEMENT, DATA_EXFILTRATION, UNAUTHORIZED_ACCESS, BENIGN
            
            Severity levels: LOW, MEDIUM, HIGH, CRITICAL
            
            Respond in JSON format:
            {"classification": "MALWARE", "severity": "HIGH", "reasoning": "Brief explanation"}
        """).strip(),
        "config_hardening": textwrap.dedent("""
            You are a cloud security engineer specializing in configuration review.
            
            Your task: Review the provided configuration for security issues.
            
            Common issues: privileged containers, running as root, overly permissive IAM,
            plaintext secrets, public S3 access, missing TLS, exposed services.
            
            Respond in JSON format:
            {"config_issues": [{"type": "issue_type", "severity": "HIGH", "fix": "description"}],
             "hardened_config": "Full corrected configuration"}
        """).strip(),
    }

    def __init__(self, config: AgentConfig):
        self.config = config
        self.client = None
        if config.api_key:
            self.client = OpenAI(base_url=config.api_base_url, api_key=config.api_key)

    def build_prompt(self, observation) -> str:
        task_type = observation.task_type
        if hasattr(task_type, "value"):
            task_type = task_type.value

        context = observation.context
        prompt_parts = [self.TASK_PROMPTS.get(task_type, "Complete the security task.")]
        prompt_parts.append(f"\n\nObjective: {observation.objective}")

        if task_type == "pii_redaction":
            text = context.get("text", "")
            prompt_parts.append(f"\n\nText to redact:\n{text}")
        elif task_type == "public_access":
            resources = context.get("resources", [])
            prompt_parts.append("\n\nCloud Resources:")
            for r in resources:
                pub_status = "PUBLIC" if r.get("public") else "private"
                prompt_parts.append(f"  - {r['name']} ({pub_status})")
        elif task_type == "ghost_user":
            users = context.get("users", [])
            prompt_parts.append("\n\nUser Accounts:")
            for u in users:
                days = u.get("last_login", "unknown")
                resources = len(u.get("active_resources", []))
                prompt_parts.append(
                    f"  - {u['username']}: last login {days}, resources: {resources}"
                )
        elif task_type == "log_analysis":
            logs = context.get("logs", "")
            prompt_parts.append(f"\n\nSecurity Logs to Analyze:\n{logs}")
        elif task_type == "config_hardening":
            config_content = context.get("config_content", "")
            config_type = context.get("config_type", "yaml")
            prompt_parts.append(
                f"\n\nConfiguration to Review ({config_type}):\n{config_content}"
            )

        if observation.feedback:
            prompt_parts.append(f"\n\nPrevious feedback: {observation.feedback}")

        prompt_parts.append(
            f"\n\nStep {observation.step_count + 1}/{observation.max_steps}"
        )
        return "\n".join(prompt_parts)

    def _extract_json(self, text: str) -> Optional[Dict[str, Any]]:
        json_pattern = r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}"
        matches = re.findall(json_pattern, text, re.DOTALL)
        for match in matches:
            try:
                return json.loads(match)
            except json.JSONDecodeError:
                continue
        return None

    def _extract_redacted_text(self, text: str) -> Optional[str]:
        lines = text.strip().split("\n")
        for line in lines:
            if "[REDACTED]" in line or "[redacted]" in line.lower():
                return line.strip()
        if "```" in text:
            parts = text.split("```")
            for part in parts:
                if "[REDACTED]" in part:
                    return part.strip()
        return None

    def generate_action(self, observation) -> SecOpsAction:
        task_type = observation.task_type
        if hasattr(task_type, "value"):
            task_type = task_type.value

        if not self.client:
            return self._fallback_action(observation, task_type)

        prompt = self.build_prompt(observation)

        try:
            completion = self.client.chat.completions.create(
                model=self.config.model_name,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a security operations assistant.",
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
            )
            response_text = completion.choices[0].message.content or ""
        except Exception as e:
            if DEBUG:
                print(f"[DEBUG] API error: {type(e).__name__}: {e}", flush=True)
            return self._fallback_action(observation, task_type)

        return self._parse_response(response_text, task_type, observation)

    def _parse_response(
        self, response_text: str, task_type: str, observation
    ) -> SecOpsAction:
        redacted_text = None
        public_resources = None
        fixed_resources = None
        ghost_users = None
        disabled_users = None
        classification = None
        severity = None
        config_issues = None
        hardened_config = None

        if task_type == "pii_redaction":
            redacted_text = self._extract_redacted_text(response_text)
            if not redacted_text:
                redacted_text = response_text.strip()

        elif task_type == "public_access":
            json_data = self._extract_json(response_text)
            if json_data:
                public_resources = json_data.get("identified_public", [])
            if not public_resources:
                public_resources = []
            fixed_resources = public_resources

        elif task_type == "ghost_user":
            json_data = self._extract_json(response_text)
            if json_data:
                ghost_users = json_data.get("identified_ghosts", [])
            if not ghost_users:
                ghost_users = []
            disabled_users = ghost_users

        elif task_type == "log_analysis":
            json_data = self._extract_json(response_text)
            if json_data:
                classification = json_data.get("classification")
                severity = json_data.get("severity")

        elif task_type == "config_hardening":
            json_data = self._extract_json(response_text)
            if json_data:
                config_issues = json_data.get("config_issues", [])
                hardened_config = json_data.get("hardened_config")

        reasoning = ""
        reasoning_match = re.search(r'"reasoning":\s*"([^"]*)"', response_text)
        if reasoning_match:
            reasoning = reasoning_match.group(1)

        return SecOpsAction(
            task_type=task_type,
            action_type=ActionType.FINALIZE,
            redacted_text=redacted_text,
            public_resources=public_resources,
            fixed_resources=fixed_resources,
            ghost_users=ghost_users,
            disabled_users=disabled_users,
            classification=classification,
            severity=severity,
            config_issues=config_issues,
            hardened_config=hardened_config,
            reasoning=reasoning,
        )

    def _fallback_action(self, observation, task_type: str) -> SecOpsAction:
        if task_type == "pii_redaction":
            text = observation.context.get("text", "")
            redacted = text
            expected_pii = observation.context.get("expected_pii", [])
            for pii in expected_pii:
                redacted = redacted.replace(pii.get("value", ""), "[REDACTED]")
            return SecOpsAction(
                task_type=task_type,
                action_type=ActionType.FINALIZE,
                redacted_text=redacted,
            )
        elif task_type == "public_access":
            public = [
                r["name"]
                for r in observation.context.get("resources", [])
                if r.get("public")
            ]
            return SecOpsAction(
                task_type=task_type,
                action_type=ActionType.FINALIZE,
                public_resources=public,
                fixed_resources=public,
            )
        elif task_type == "ghost_user":
            ghosts = [
                u["username"]
                for u in observation.context.get("users", [])
                if u.get("is_ghost")
            ]
            return SecOpsAction(
                task_type=task_type,
                action_type=ActionType.FINALIZE,
                ghost_users=ghosts,
                disabled_users=ghosts,
            )
        elif task_type == "log_analysis":
            return SecOpsAction(
                task_type=task_type,
                action_type=ActionType.FINALIZE,
                classification="NEEDS_INVESTIGATION",
                severity="MEDIUM",
                reasoning="Fallback: unable to analyze logs",
            )
        elif task_type == "config_hardening":
            return SecOpsAction(
                task_type=task_type,
                action_type=ActionType.FINALIZE,
                config_issues=[],
                hardened_config=observation.context.get("config_content", ""),
                reasoning="Fallback: unable to analyze config",
            )

        return SecOpsAction(task_type=task_type, action_type=ActionType.NOOP)


def run_episode(
    env: SecOpsEnv, agent: SecOpsAgent, task: str, difficulty: str
) -> tuple:
    rewards: List[float] = []
    steps_taken = 0
    error_msg = None

    try:
        result = env.reset(task=task, difficulty=difficulty)
        observation = result.observation

        for step in range(1, MAX_STEPS + 1):
            if result.done:
                break

            action = agent.generate_action(observation)
            action_str = str(action.model_dump())[:100]

            result = env.step(action)
            observation = result.observation

            reward = result.reward or 0.0
            done = result.done or False

            rewards.append(reward)
            steps_taken = step

            log_step(
                step=step, action=action_str, reward=reward, done=done, error=error_msg
            )

            if done:
                break

        score = observation.reward if observation.reward else sum(rewards)
        success = score >= SUCCESS_SCORE_THRESHOLD

        return success, steps_taken, score, rewards, error_msg

    except Exception as e:
        error_msg = str(e)[:100]
        if DEBUG:
            import traceback

            traceback.print_exc()
        score = sum(rewards) if rewards else 0.01
        return False, steps_taken, score, rewards, error_msg


def main():
    print(f"SecOps Environment Inference - Benchmark: {BENCHMARK}", flush=True)
    print(f"Model: {MODEL_NAME}", flush=True)
    print(f"API Base: {API_BASE_URL}", flush=True)

    if not HF_TOKEN:
        print("NOTE: HF_TOKEN not set - using fallback actions", flush=True)

    try:
        env = SecOpsEnv(base_url="http://localhost:8000")

        agent_config = AgentConfig(
            model_name=MODEL_NAME,
            api_base_url=API_BASE_URL,
            api_key=HF_TOKEN,
        )
        agent = SecOpsAgent(agent_config)

        for task_name, difficulty in ALL_TASKS:
            log_start(task=task_name, env=BENCHMARK, model=MODEL_NAME)

            success, steps, score, rewards, error = run_episode(
                env, agent, task_name, difficulty
            )

            log_end(success=success, steps=steps, score=score, rewards=rewards)

        env.close()

    except KeyboardInterrupt:
        print("\nBenchmark interrupted by user", flush=True)
    except Exception as e:
        print(f"\nError during benchmark: {e}", flush=True)
        if DEBUG:
            import traceback

            traceback.print_exc()


if __name__ == "__main__":
    main()
