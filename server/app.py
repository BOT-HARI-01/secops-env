"""
SecOps Environment - FastAPI Server Application.
"""

from contextlib import asynccontextmanager
from typing import Optional, Dict, Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from secops_env.server.secops_environment import SecOpsEnvironment
from secops_env.models import SecOpsAction, SecOpsObservation


class ResetRequest(BaseModel):
    task: Optional[str] = None
    difficulty: Optional[str] = None
    seed: Optional[int] = None


class StepRequest(BaseModel):
    action: Dict[str, Any]


class ResetResponse(BaseModel):
    observation: Dict[str, Any]
    reward: float
    done: bool
    info: Dict[str, Any]


class StepResponse(BaseModel):
    observation: Dict[str, Any]
    reward: float
    done: bool
    info: Dict[str, Any]


env = SecOpsEnvironment()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage environment lifecycle."""
    yield
    pass


app = FastAPI(
    title="SecOps Environment",
    description="Security Operations Environment for OpenEnv - AI Safety Auditing",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "environment": "secops_env"}


@app.post("/reset", response_model=ResetResponse)
async def reset(request: ResetRequest):
    """Reset the environment for a new episode."""
    try:
        result = env.reset(
            task=request.task, difficulty=request.difficulty, seed=request.seed
        )

        obs_dict = result.model_dump() if hasattr(result, "model_dump") else {}
        if not obs_dict:
            obs_dict = {
                "task_type": str(result.task_type),
                "task_difficulty": str(result.task_difficulty),
                "objective": result.objective,
                "context": result.context,
                "available_actions": result.available_actions,
                "current_state": result.current_state,
                "partial_progress": result.partial_progress,
                "step_count": result.step_count,
                "max_steps": result.max_steps,
                "feedback": result.feedback,
                "detected_issues": result.detected_issues,
                "fixed_issues": result.fixed_issues,
                "reward": result.reward,
                "done": result.done,
                "success": result.success,
                "metadata": result.metadata,
            }

        return ResetResponse(
            observation=obs_dict, reward=0.0, done=False, info=result.metadata or {}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/step", response_model=StepResponse)
async def step(request: StepRequest):
    """Execute an action in the environment."""
    try:
        action = SecOpsAction(**request.action)
        result = env.step(action)

        obs_dict = result.model_dump() if hasattr(result, "model_dump") else {}
        if not obs_dict or not isinstance(obs_dict, dict):
            obs_dict = {
                "task_type": str(result.task_type),
                "task_difficulty": str(result.task_difficulty),
                "objective": result.objective,
                "context": result.context,
                "available_actions": result.available_actions,
                "current_state": result.current_state,
                "partial_progress": result.partial_progress,
                "step_count": result.step_count,
                "max_steps": result.max_steps,
                "feedback": result.feedback,
                "detected_issues": result.detected_issues,
                "fixed_issues": result.fixed_issues,
                "reward": result.reward,
                "done": result.done,
                "success": result.success,
                "metadata": result.metadata,
            }

        return StepResponse(
            observation=obs_dict,
            reward=result.reward or 0.0,
            done=result.done or False,
            info=result.metadata or {},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/state")
async def get_state():
    """Get current environment state."""
    try:
        state = env.state
        return {
            "episode_id": state.episode_id,
            "step_count": state.step_count,
            "task_type": state.task_type,
            "accumulated_reward": env.get_reward(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "name": "SecOps Environment",
        "version": "0.1.0",
        "description": "Security Operations Environment for OpenEnv",
        "tasks": [
            "pii_redaction",
            "public_access",
            "ghost_user",
            "log_analysis",
            "config_hardening",
        ],
    }


def main():
    """Entry point for running the server."""
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
