from logging import getLogger
from threading import Lock

from werkzeug.local import LocalStack, release_local

from spire.exceptions import LocalError

log = getLogger(__name__)

class StackProxy(object):
    def __init__(self, manager, token):
        self.manager = manager
        self.token = token

    def get(self, default=None):
        return self.manager.get(self.token, default)

    def push(self, value, finalizer=None):
        return self.manager.push(self.token, value, finalizer)

    def pop(self):
        return self.manager.pop(self.token)

    def require(self):
        return self.manager.require(self.token)

class PrefixedProxy(object):
    def __init__(self, manager, prefix):
        self.manager = manager
        self.prefix = [prefix]

    def declare(self, token):
        return self.manager.declare(self._apply_prefix(token))

    def get(self, token):
        return self.manager.get(self._apply_prefix(token))

    def push(self, token, value, finalizer=None):
        return self.manager.push(self._apply_prefix(token), value, finalizer)

    def pop(self, token):
        return self.manager.pop(self._apply_prefix(token))

    def require(self, token):
        return self.manager.require(self._apply_prefix(token))

    def _apply_prefix(self, token):
        if isinstance(token, tuple):
            token = list(token)
        else:
            token = [token]
        return tuple(self.prefix + token)

class ContextLocalManager(object):
    def __init__(self):
        self.guard = Lock()
        self.locals = {}

    def create_prefixed_proxy(self, prefix):
        return PrefixedProxy(self, prefix)

    def declare(self, token):
        self.guard.acquire()
        try:
            if token not in self.locals:
                self.locals[token] = LocalStack()
            return StackProxy(self, token)
        finally:
            self.guard.release()

    def get(self, token, default=None):
        pair = self.locals[token].top
        if pair is not None:
            return pair[0]
        else:
            return default

    def push(self, token, value, finalizer=None):
        #log.debug('pushing value %r onto stack %r' % (value, token))
        self.locals[token].push((value, finalizer))
        return value

    def pop(self, token):
        value, finalizer = self.locals[token].pop()
        #log.debug('popping value %r off stack %r' % (value, token))
        if finalizer:
            #log.debug('running finalizer for %r off stack %r' % (value, token))
            finalizer()
        return value

    def purge(self):
        #log.debug('purging context locals')
        for stack in self.locals.itervalues():
            while stack.top is not None:
                value, finalizer = stack.pop()
                if finalizer:
                    finalizer()

    def require(self, token):
        pair = self.locals[token].top
        if pair is not None:
            return pair[0]
        else:
            raise LocalError(token)

ContextLocals = ContextLocalManager()
purge_context_locals = ContextLocals.purge
