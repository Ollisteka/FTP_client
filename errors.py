# Exception raised when an error or invalid response is received
class Error(Exception):
    pass


class ReplyError(Error):
    """Positive Preliminary, Completion and Intermediate reply, 1xx"""
    pass


class TransientError(Error):
    """Transient Negative Completion reply, 4xx"""
    pass


class PermanentError(Error):
    """Permanent Negative Completion reply, 5xx"""
    pass


class ProtectedError(Error):
    """Protected reply, 6xx"""
    pass

# All exceptions (hopefully) that may be raised here and that aren't
# (always) programming errors on our side
all_errors = (Error, OSError, EOFError)