class CadresecError(Exception):
    """Base error class for Cadresec framework."""
    pass

class ScopeViolationError(CadresecError):
    """Raised when a target or action is outside the Rules of Engagement scope."""
    pass

class ApprovalViolationError(CadresecError):
    """Raised when human approval is denied or fails for a tool invocation."""
    pass

class DestructiveToolError(CadresecError):
    """Raised when a destructive tool is requested (unsupported by the framework)."""
    pass

class EngagementKilledError(CadresecError):
    """Raised when an operation is attempted on a session that has been killed."""
    pass

class InvalidRoEError(CadresecError):
    """Raised when a Rules of Engagement configuration is missing, expired, or invalid."""
    pass

class SandboxUnavailableError(CadresecError):
    """Raised when the required tool execution sandbox is unavailable."""
    pass
