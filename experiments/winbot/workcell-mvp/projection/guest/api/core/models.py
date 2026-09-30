"""Control policy models — shared between broker and API endpoints.
Compatible with WineBot's api/core/models.py for agent interchangeability."""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class ControlMode(str, Enum):
    USER = "USER"
    AGENT = "AGENT"


class ControlPolicyMode(str, Enum):
    HUMAN_ONLY = "human-only"
    AGENT_ONLY = "agent-only"
    HYBRID = "hybrid"


class UserIntent(str, Enum):
    WAIT = "WAIT"
    SAFE_INTERRUPT = "SAFE_INTERRUPT"
    STOP_NOW = "STOP_NOW"


class AgentStatus(str, Enum):
    IDLE = "IDLE"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"


class ControlState(BaseModel):
    session_id: str
    interactive: bool
    control_mode: ControlMode
    lease_expiry: Optional[float] = None
    user_intent: UserIntent
    agent_status: AgentStatus
    instance_control_mode: ControlPolicyMode = ControlPolicyMode.HYBRID
    session_control_mode: ControlPolicyMode = ControlPolicyMode.HYBRID
    effective_control_mode: ControlPolicyMode = ControlPolicyMode.HYBRID


class GrantControlModel(BaseModel):
    lease_seconds: int = Field(ge=1, le=86400)
    user_ack: bool = False
    challenge_token: Optional[str] = None


class UserIntentModel(BaseModel):
    intent: UserIntent


class ControlPolicyModeModel(BaseModel):
    mode: ControlPolicyMode


class ChallengeResponse(BaseModel):
    token: str
    expires_epoch: float
