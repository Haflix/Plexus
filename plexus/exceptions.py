class ConfigException(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class RequestException(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class NetworkRequestException(RequestException):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


# locked #13: typed exception for "no local subscriber matched" path on
# request_event / request_event_stream remote dispatch. Distinct from
# NetworkRequestException so caller fall-through can keep the strict
# semantics of locked #6.
class NoLocalSubException(RequestException):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


# Rate-limiter Step 2b: a plugin asserted an identity (author/author_id) it is
# not authorized to claim -- claiming "system" without the system_caller grant,
# impersonating a plugin without impersonation_allowed (or out of scope), or
# starting a second, different impersonation inside an already-impersonating
# chain (no-chaining). The capability gate fails CLOSED: it raises this BEFORE
# the call dispatches. Subclasses RequestException so existing
# ``except RequestException`` handlers still catch it, while callers may
# ``except CapabilityException`` for the specific denial.
class CapabilityException(RequestException):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class NodeException(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class PluginTypeMismatchError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class PluginDependencyError(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)
