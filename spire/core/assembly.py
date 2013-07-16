from threading import RLock, local

from spire.core.registry import Registry
from spire.exceptions import *
from spire.support.logs import LogHelper
from spire.util import import_object, recursive_merge

__all__ = ('Assembly', 'adhoc_configure', 'get_unit')

log = LogHelper('spire.core')

class Local(local):
    assembly = None

class Assembly(object):
    """A spire assembly."""

    local = Local()
    standard = None

    def __init__(self):
        self.cache = {}
        self.configuration = {}
        self.guard = RLock()
        self.pending = {}
        self.principals = {}

    def __enter__(self):
        self.promote()

    def __exit__(self, *args):
        self.demote()

    def __repr__(self):
        return 'Assembly(0x%08x)' % id(self)

    def acquire(self, key, instantiator, arguments):
        self.guard.acquire()
        try:
            try:
                return self.cache[key]
            except KeyError:
                instance = self.cache[key] = instantiator(*arguments)
                return instance
        finally:
            self.guard.release()

    def collate(self, superclass, single=False):
        units = set()
        for unit in self.cache.values():
            if isinstance(unit, superclass):
                units.add(unit)
            for dependency in unit.dependencies.itervalues():
                if issubclass(dependency.unit, superclass):
                    units.add(dependency.get(unit))

        if not single:
            return units
        elif len(units) > 1:
            raise Exception()
        elif units:
            return units.pop()
        else:
            return None

    @classmethod
    def current(cls):
        return cls.local.assembly or cls.standard

    def configure(self, configuration):
        schemas = Registry.schemas
        for token, data in configuration.iteritems():
            schema = schemas.get(token)
            if schema:
                data = schema.process(data, serialized=True)
                recursive_merge(self.configuration, {token: data})
            else:
                recursive_merge(self.pending, {token: data})

    def demote(self):
        if self.local.assembly is self:
            self.local.assembly = None
        return self

    def filter_configuration(self, prefix):
        if prefix[-1] != ':':
            prefix += ':'

        filtered = {}
        for token, data in self.configuration.iteritems():
            if token.startswith(prefix):
                filtered[token] = data
        return filtered

    def get_configuration(self, token):
        try:
            return self.configuration[token]
        except KeyError:
            pass

        self.guard.acquire()
        try:
            schemas = Registry.schemas
            for token in self.pending.keys():
                schema = schemas.get(token)
                if schema:
                    data = schema.process(self.pending.pop(token), serialized=True)
                    recursive_merge(self.configuration, {token: data})
        finally:
            self.guard.release()

        return self.configuration[token]

    def instantiate(self, unit):
        if isinstance(unit, basestring):
            unit = import_object(unit)
        return self.acquire(unit.identity, unit, ())

    def should_isolate(self, identity):
        identity += '/'
        length = len(identity)

        for key in self.configuration:
            if key[:length] == identity:
                return True
        else:
            return False

    def promote(self):
        self.local.assembly = self
        return self

Assembly.standard = Assembly()

def adhoc_configure(configuration):
    Assembly.current().configure(configuration)

def get_unit(unit):
    return Assembly.current().instantiate(unit)
