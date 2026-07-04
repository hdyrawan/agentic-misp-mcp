class AgenticMispMCPError(Exception):
    """Base project exception."""


class ConfigurationError(AgenticMispMCPError):
    """Configuration is invalid."""


class MISPClientError(AgenticMispMCPError):
    """MISP client request failed."""


class MISPAuthenticationError(MISPClientError):
    """MISP authentication or authorization failed."""


class MISPRateLimitError(MISPClientError):
    """MISP rate limit was reached."""


class MISPNotFoundError(MISPClientError):
    """Requested MISP resource was not found."""


class WorkflowError(AgenticMispMCPError):
    """Workflow execution failed."""
