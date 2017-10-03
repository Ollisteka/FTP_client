# Exception raised when an error or invalid response is received
class Error(Exception):
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
