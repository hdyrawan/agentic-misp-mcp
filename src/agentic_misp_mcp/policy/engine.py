from __future__ import annotations

from dataclasses import dataclass

from agentic_misp_mcp.policy.models import Action, PolicyDecision, Role


@dataclass(frozen=True)
class PolicyEngine:
    """Evaluate role/action policy before workflow execution."""

    role: Role = Role.READ_ONLY
    enable_write: bool = False
    require_approval: bool = True

    @classmethod
    def from_settings(cls, settings: object) -> PolicyEngine:
        return cls(
            role=Role(str(getattr(settings, "policy_role", Role.READ_ONLY.value))),
            enable_write=bool(getattr(settings, "enable_write", False)),
            require_approval=bool(getattr(settings, "require_approval", True)),
        )

    def decide(self, *, tool_name: str, action: Action | str) -> PolicyDecision:
        action_value = Action(str(action))

        if action_value is Action.READ:
            return self._decision(
                tool_name=tool_name,
                action=action_value,
                allowed=True,
                approval_required=False,
                reason="read actions are allowed for all configured roles",
            )

        if not self.enable_write:
            return self._decision(
                tool_name=tool_name,
                action=action_value,
                allowed=False,
                approval_required=False,
                reason="write mode is disabled by AGENTIC_MISP_MCP_ENABLE_WRITE",
            )

        if self.role is Role.READ_ONLY:
            return self._decision(
                tool_name=tool_name,
                action=action_value,
                allowed=False,
                approval_required=False,
                reason="read_only role cannot perform non-read actions",
            )

        if action_value is Action.WRITE:
            allowed = self.role in {Role.ANALYST_WRITE, Role.CURATOR, Role.ADMIN}
            return self._decision(
                tool_name=tool_name,
                action=action_value,
                allowed=allowed,
                approval_required=allowed and self.require_approval,
                reason=(
                    "write action allowed by role and requires approval"
                    if allowed and self.require_approval
                    else "write action allowed by role"
                    if allowed
                    else f"{self.role.value} role cannot perform write actions"
                ),
            )

        if action_value is Action.PUBLISH:
            allowed = self.role in {Role.CURATOR, Role.ADMIN}
            return self._decision(
                tool_name=tool_name,
                action=action_value,
                allowed=allowed,
                approval_required=allowed and self.require_approval,
                reason=(
                    "publish action allowed by curator/admin role and requires approval"
                    if allowed and self.require_approval
                    else "publish action allowed by curator/admin role"
                    if allowed
                    else f"{self.role.value} role cannot perform publish actions"
                ),
            )

        if action_value is Action.SYNC:
            allowed = self.role in {Role.CURATOR, Role.ADMIN}
            return self._decision(
                tool_name=tool_name,
                action=action_value,
                allowed=allowed,
                approval_required=allowed and self.require_approval,
                reason=(
                    "sync/feed-like action allowed by curator/admin role and requires approval"
                    if allowed and self.require_approval
                    else "sync/feed-like action allowed by curator/admin role"
                    if allowed
                    else f"{self.role.value} role cannot perform sync/feed-like actions"
                ),
            )

        if action_value is Action.ADMIN:
            allowed = self.role is Role.ADMIN
            return self._decision(
                tool_name=tool_name,
                action=action_value,
                allowed=allowed,
                approval_required=allowed and self.require_approval,
                reason=(
                    "admin action allowed by admin role and requires approval"
                    if allowed and self.require_approval
                    else "admin action allowed by admin role"
                    if allowed
                    else f"{self.role.value} role cannot perform admin actions"
                ),
            )

        return self._decision(
            tool_name=tool_name,
            action=action_value,
            allowed=False,
            approval_required=False,
            reason="dangerous actions are not executable in the policy foundation",
        )

    def _decision(
        self,
        *,
        tool_name: str,
        action: Action,
        allowed: bool,
        approval_required: bool,
        reason: str,
    ) -> PolicyDecision:
        return PolicyDecision(
            allowed=allowed,
            approval_required=approval_required,
            reason=reason,
            role=self.role.value,
            action=action.value,
            tool_name=tool_name,
        )


def enforce_policy(decision: PolicyDecision) -> None:
    """Raise PermissionError when a policy decision blocks execution."""

    if not decision.allowed:
        raise PermissionError(decision.reason)
