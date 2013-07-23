from copy import deepcopy

from scheme import Structure

from spire.core.assembly import Assembly
from spire.core.registry import Registry
from spire.exceptions import *

class Dependency(object):
    """A spire dependency."""

    def __init__(self, unit, token=None, optional=False, deferred=True, **params):
        if token is None:
            token = unit.identity

        self.attr = None
        self.cache = {}
        self.deferred = deferred
        self.dependent = None
        self.optional = optional
        self.token = token
        self.unit = unit

        if params:
            if self.configurable:
                self.params = self.unit.configuration.process(params, partial=True)
            else:
                raise Exception()
        else:
            self.params = params

    def __get__(self, instance, owner):
        if instance is not None:
            return self.get(instance)
        else:
            return self

    def __repr__(self):
        return '%s(%r)' % (type(self).__name__, self.token)

    @property
    def configurable(self):
        return bool(self.unit.configuration)

    @property
    def configuration_required(self):
        return (self.unit.configuration and self.unit.configuration.required
            and not self.optional)

    def bind(self, unit, attr):
        self.attr = attr
        self.dependent = unit
        return self

    def clone(self):
        dependency = deepcopy(self)
        dependency.attr = dependency.dependent = None
        dependency.cache = {}
        return dependency

    def construct_schema(self, generic=False, **params):
        parameters = self.contribute_params()
        if not generic:
            parameters.update(self.params)

        configuration = self.unit.configuration
        if not parameters:
            return configuration.schema.clone(required=configuration.required, **params)

        fields = {}
        for name, field in configuration.schema.structure.iteritems():
            if name in parameters:
                fields[name] = field.clone(default=parameters[name], required=False)
            else:
                fields[name] = field

        structure = Structure(fields, nonnull=True, **params)
        structure.required = structure.has_required_fields
        return structure

    def contribute_params(self):
        return {}

    def get(self, instance=None):
        try:
            return self.cache[instance]
        except AttributeError:
            hashable = False
        except KeyError:
            hashable = True

        identity = None
        token = None

        assembly = Assembly.current()
        if instance:
            identity = '%s/%s' % (instance.__identity__, self.attr)
            if identity in assembly.configuration:
                token = identity

        if not token:
            if self.token:
                token = self.token
                #if token not in assembly.configuration and self.configuration_required:
                #    raise ConfigurationError(token)
                if identity and not assembly.should_isolate(identity):
                    identity = None
            else:
                token = identity

        key = (token, identity, self.unit)
        dependency = assembly.acquire(key, self.instantiate, (assembly, token, identity, instance))

        if hashable:
            self.cache[instance] = dependency
        return dependency

    def instantiate(self, assembly, token, identity, parent):
        params = self.contribute_params()
        params.update(self.params)
        if hasattr(parent, 'contribute_params'):
            params.update(parent.contribute_params())
        return self.unit(__assembly__=assembly, __identity__=identity,
            __token__=token, **params)

    @classmethod
    def register(cls, *args, **params):
        Registry.register_dependency(cls(*args, **params))
