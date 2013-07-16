from scheme import Structure

__all__ = ('Configuration', 'configured_property')

class Configuration(object):
    """A unit configuration definition."""

    def __init__(self, schema=None):
        schema = schema or {}
        if isinstance(schema, dict):
            schema = Structure(schema, nonnull=True)
        if not isinstance(schema, Structure):
            raise Exception()

        self.cache = {}
        self.schema = schema
        self.subject = None

    def __get__(self, instance, owner):
        if instance is not None:
            return self.get(instance)
        else:
            return self

    @property
    def required(self):
        return self.schema.has_required_fields

    def bind(self, unit):
        self.subject = unit
        return self

    def get(self, instance):
        try:
            return self.cache[instance]
        except KeyError:
            pass

        token = instance.__token__
        try:
            configuration = instance.__assembly__.get_configuration(token)
        except KeyError:
            configuration = self.schema.generate_default()

        self.cache[instance] = configuration
        return configuration

    def process(self, data, partial=False):
        return self.schema.process(data, serialized=True, partial=partial)

class configured_property(object):
    """A property which delegates to a unit's configuration."""

    def __init__(self, key):
        self.key = key

    def __get__(self, instance, owner):
        if instance is not None:
            return instance.configuration[self.key]
        else:
            return self
