from collections import deque
from thread import error as ThreadError, get_ident, start_new_thread
from threading import Lock
from time import sleep, time

from scheme import Integer

from spire.core import Configuration, Unit, configured_property
from spire.support.logs import LogHelper

log = LogHelper(__name__)

class RetireThread(Exception):
    """Retires a thread."""

class PooledThread(object):
    """A pooled thread."""

    def __init__(self, pool, identifier):
        self.cycle = Lock()
        self.identifier = identifier
        self.package = None
        self.pool = pool
        self.running = True

        self.cycle.acquire()
        self.id = start_new_thread(self.run, ())

    def __repr__(self):
        return 'PooledThread(%r)' % self.identifier

    def assign(self, package):
        self.package = package
        self.cycle.release()

    def idle(self):
        cycle, pool = self.cycle, self.pool
        timeout = time() + pool.idle_timeout

        while True:
            sleep(0.1)
            remaining = timeout - time()
            if remaining <= 0:
                if pool._confirm_retirement(self):
                    raise RetireThread()
                else:
                    break
            elif cycle.acquire(0):
                break

    def run(self):
        cycle, pool = self.cycle, self.pool
        try:
            while True:
                cycle.acquire()
                if self.package is False:
                    self.idle()
                if self.package is not None:
                    package = self.package
                    if package:
                        try:
                            package()
                        except Exception:
                            log('exception', 'package %r raised exception', package)
                    self.package = None
                    with pool.guard:
                        if pool._request_package(self) is False:
                            raise RetireThread()
                else:
                    raise RetireThread()
        except RetireThread:
            pass
        except Exception:
            log('exception', 'uncaught exception within %r', self)
        finally:
            self.running = False

class ThreadPool(Unit):
    """A thread pool."""

    configuration = Configuration({
        'idle_threshold': Integer(nonnull=True, minimum=0, default=4),
        'idle_timeout': Integer(nonnull=True, minimum=0, default=300),
        'maximum_threads': Integer(nonnull=True, minimum=1, default=16),
        'minimum_threads': Integer(nonnull=True, minimum=0, default=0),
    })

    idle_threshold = configured_property('idle_threshold')
    idle_timeout = configured_property('idle_timeout')
    maximum_threads = configured_property('maximum_threads')
    minimum_threads = configured_property('minimum_threads')

    def __init__(self):
        self.activity = None
        self.counter = 0
        self.guard = Lock()
        self.idle = deque()
        self.pending = deque()
        self.spare = None
        self.threads = {}

    def enqueue(self, package):
        with self.guard:
            if self.idle:
                self.idle.pop().assign(package)
            elif self.spare:
                self.spare.assign(package)
                self.spare = None
            elif len(self.threads) < self.maximum_threads:
                self._grow_pool().assign(package)
            else:
                self.pending.append(package)

    def _confirm_retirement(self, thread):
        with self.guard:
            if not thread.cycle.acquire(0):
                self._retire_thread(thread, False)
                if self.spare is thread:
                    self.spare = None
                self._idle_thread()
                return True

    def _grow_pool(self):
        self.counter += 1
        thread = PooledThread(self, self.counter)

        self.threads[thread.identifier] = thread
        return thread

    def _idle_thread(self):
        if (not self.spare and len(self.threads) > self.minimum_threads
            and len(self.idle) > self.idle_threshold):
            self.spare = self.idle.popleft()
            self.spare.assign(False)

    def _request_package(self, thread):
        activity = self.activity
        if not activity:
            if self.pending:
                thread.assign(self.pending.popleft())
            else:
                self._idle_thread()
                self.idle.append(thread)
        elif activity == 'shrink':
            excess = len(self.threads) - self.maximum_threads
            if excess >= 1:
                self._retire_thread(thread)
            if excess == 1:
                self.activity = None

    def _retire_thread(self, thread, shutdown=True):
        del self.threads[thread.identifier]
        if shutdown:
            thread.assign(None)
