"""Control policy endpoints — compatible with WineBot api/routers/control.py.
Provides human-in-the-loop agent control: lease grants, challenge tokens,
user intent signaling, and control mode management."""

from core.broker import broker
from core.models import (
    ChallengeResponse,
    ControlPolicyModeModel,
    GrantControlModel,
    UserIntentModel,
)
from fastapi import APIRouter

router = APIRouter(prefix="/control", tags=["Control"])


# ── Instance-level control mode ──

@router.get("/mode", response_model=dict)
async def get_instance_control_mode():
    """Get the instance-level control policy mode."""
    state = broker.get_state()
    return {
        "mode": state.instance_control_mode.value,
        "effective_mode": state.effective_control_mode.value,
    }


@router.post("/mode", response_model=dict)
async def set_instance_control_mode(body: ControlPolicyModeModel):
    """Set the instance-level control policy mode."""
    await broker.set_instance_control_mode(body.mode)
    state = broker.get_state()
    return {
        "mode": state.instance_control_mode.value,
        "effective_mode": state.effective_control_mode.value,
    }


# ── Session-level control ──

@router.get("/sessions/{session_id}/control", response_model=dict)
async def get_session_control(session_id: str):
    """Get the control state for a session."""
    state = broker.get_state()
    return {
        "session_id": state.session_id,
        "control_mode": state.control_mode.value,
        "interactive": state.interactive,
        "user_intent": state.user_intent.value if state.user_intent else None,
        "agent_status": state.agent_status.value,
        "lease_expiry": state.lease_expiry,
        "effective_control_mode": state.effective_control_mode.value,
        "session_control_mode": state.session_control_mode.value,
        "instance_control_mode": state.instance_control_mode.value,
    }


@router.post("/sessions/{session_id}/control/grant", response_model=dict)
async def grant_agent_control(session_id: str, body: GrantControlModel):
    """Grant agent control with a lease and challenge token."""
    await broker.grant_agent(
        lease_seconds=body.lease_seconds,
        user_ack=body.user_ack,
        challenge_token=body.challenge_token or "",
    )
    state = broker.get_state()
    return {
        "granted": state.control_mode == "AGENT",
        "lease_expiry": state.lease_expiry,
        "session_id": session_id,
    }


@router.post("/sessions/{session_id}/control/renew", response_model=dict)
async def renew_agent_control(session_id: str, lease_seconds: int = 300):
    """Renew the agent's control lease."""
    await broker.renew_agent(lease_seconds)
    state = broker.get_state()
    return {
        "renewed": True,
        "lease_expiry": state.lease_expiry,
        "session_id": session_id,
    }


@router.post("/sessions/{session_id}/control/challenge", response_model=ChallengeResponse)
async def issue_challenge(session_id: str, ttl_seconds: int = 30):
    """Issue a one-time challenge token for granting agent control."""
    result = await broker.issue_grant_challenge(ttl_seconds)
    return ChallengeResponse(**result)


@router.post("/sessions/{session_id}/user_intent", response_model=dict)
async def set_user_intent(session_id: str, body: UserIntentModel):
    """Set the user's intent signal."""
    await broker.set_user_intent(body.intent)
    state = broker.get_state()
    return {
        "user_intent": state.user_intent.value,
        "control_mode": state.control_mode.value,
        "session_id": session_id,
    }


@router.get("/sessions/{session_id}/control/mode", response_model=dict)
async def get_session_control_mode(session_id: str):
    """Get the session-level control mode."""
    state = broker.get_state()
    return {
        "session_id": session_id,
        "session_control_mode": state.session_control_mode.value,
        "effective_control_mode": state.effective_control_mode.value,
    }


@router.post("/sessions/{session_id}/control/mode", response_model=dict)
async def set_session_control_mode(session_id: str, body: ControlPolicyModeModel):
    """Set the session-level control mode."""
    await broker.set_session_control_mode(body.mode)
    state = broker.get_state()
    return {
        "session_id": session_id,
        "session_control_mode": state.session_control_mode.value,
        "effective_control_mode": state.effective_control_mode.value,
    }


# ── Control health/info ──

@router.get("/state", response_model=dict)
async def get_full_control_state():
    """Get the complete control state (for debugging)."""
    state = broker.get_state()
    return state.model_dump()


@router.post("/report/user_activity")
async def report_user_activity():
    """Report that the user is active (revokes agent if needed)."""
    await broker.report_user_activity()
    return {"status": "ok"}


@router.post("/report/agent_activity")
async def report_agent_activity():
    """Report that the agent is active."""
    await broker.report_agent_activity()
    return {"status": "ok"}
