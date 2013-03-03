from copy import deepcopy

from spire.core.assembly import Assembly
from spire.core.configuration import Configuration
from spire.core.dependency import Dependency
from spire.core.registry import Configurable, Registry
from spire.exceptions import *
from spire.support.logs import LogHelper
from spire.util import get_constructor_args, identify_object

__all__ = ('Component', 'ConfigurableUnit', 'Unit')

log = LogHelper('spire.core')

class UnitMeta(type):
    def __new__(metatype, name, bases, namespace):
        secondary = None
        for base in reversed(bases):
            metaclass = getattr(base, '__metaclass__', None)
            if metaclass and metaclass is not metatype:
                if not secondary:
                    secondary = metaclass
                elif metaclass is not secondary:
                    raise SpireError('cannot reconcile more then two metaclass bases')

        unit = None
        if secondary:
            metatype = type('metaclass', (metatype, secondary), {
                '__secondary_metaclass__': secondary})
            unit = secondary.__new__(metatype, name, bases, namespace)
            unit.__metaclass__ = metatype
        else:
            for base in reversed(bases):
                candidate = getattr(base, '__secondary_metaclass__', None)
                if candidate:
                    if not secondary:
                        secondary = candidate
                    elif candidate is not secondary:
                        raise SpireError()
            
            secondary = secondary or type
            unit = secondary.__new__(metatype, name, bases, namespace)

        unit.identity = identify_object(unit)
        configuration = {}
        dependencies = {}

        for base in reversed(bases):
            inherited_configuration = getattr(base, 'configuration', None)
            if isinstance(inherited_configuration, Configuration):
                configuration.update(inherited_configuration.schema.structure)

            inherited_dependencies = getattr(base, 'dependencies', None)
            if inherited_dependencies:
                dependencies.update(inherited_dependencies)

        declared_configuration = namespace.get('configuration')
        if isinstance(declared_configuration, Configuration):
            declared_configuration.schema.merge(configuration)
            declared_configuration.bind(unit)
        else:
            if isinstance(declared_configuration, dict):
                configuration.update(declared_configuration)
            if configuration:
                unit.configuration = Configuration(configuration).bind(unit)

        unit.dependencies = {}
        for attr, value in namespace.iteritems():
            if isinstance(value, Dependency):
                Registry.register_dependency(value)
                unit.dependencies[attr] = value.bind(unit, attr)

        for name, dependency in dependencies.iteritems():
            if name not in unit.dependencies:
                dependency = dependency.clone().bind(unit, name)
                unit.dependencies[name] = dependency
                setattr(unit, name, dependency)

        Registry.register_unit(unit)
        return unit

    def __call__(cls, *args, **params):
        assembly = params.pop('__assembly__', None)
        if not assembly:
            assembly = Assembly.current()

        identity = params.pop('__identity__', None)
        token = params.pop('__token__', None)

        if not token:
            token = identity = cls.identity

        signature = get_constructor_args(cls)
        if args:
            for i, argument in enumerate(args):
                try:
                    name = signature[i]
                    if name not in params:
                        params[name] = argument
                    else:
                        raise TypeError('duplicate arguments')
                except IndexError:
                    raise TypeError('too many arguments')

        unit = cls.__new__(cls)
        unit.__assembly__ = assembly
        unit.__identity__ = identity
        unit.__token__ = token

        #log('debug', 'instantiating unit %s: token=%r, identity=%r',
        #    cls.identity, token, identity)

        if cls.configuration:
            configuration = cls.configuration.get(unit)
            if params:
                for name, value in params.items():
                    configuration[name] = value
                    if name not in signature:
                        del params[name]

            for name in signature:
                if name in configuration:
                    params[name] = configuration[name]

        for dependency in cls.dependencies.itervalues():
            if not dependency.deferred:
                dependency.get(unit)

        unit.__init__(**params)

        return unit

class Unit(object):
    """A spire unit."""

    __metaclass__ = UnitMeta

    configuration = None
    dependencies = None
    identity = None

    def collate_dependencies(self, cls=None):
        for dependency in self.dependencies.itervalues():
            if (cls is None or issubclass(dependency.unit, cls)):
                yield dependency.get(self)

    @classmethod
    def deploy(cls, deferred=False, **params):
        return Dependency(cls, False, deferred=deferred, **params)

class ConfigurableUnit(Unit, Configurable):
    """A unit which can be directly configured."""

class Component(Unit, Configurable):
    """A component."""
