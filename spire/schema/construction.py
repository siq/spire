from spire.mesh.units import Definition, DefinitionType, Surrogate, SurrogateType
from spire.schema.fields import *

EQUIVALENTS = {
    'binary': None,
    'boolean': BooleanType,
    'date': DateType,
    'datetime': DateTimeType,
    'decimal': DecimalType,
    'definition': DefinitionType,
    'enumeration': EnumerationType,
    'float': FloatType,
    'integer': IntegerType,
    'surrogate': SurrogateType,
    'text': TextType,
    'time': TimeType,
}

class FieldConstructor(object):
    """A schema field constructor."""

    def __init__(self, use_json_for_map=False, use_json_for_structure=False):
        self.use_json_for_map = use_json_for_map
        self.use_json_for_structure = use_json_for_structure

    def construct(self, field):
        method = 'construct_' + field.basetype
        try:
            method = getattr(self, method)
        except AttributeError:
            raise ValueError(field)
        else:
            return method(field)

    def construct_binary(self, field):
        raise ValueError(field)

    def construct_boolean(self, field):
        return Boolean(name=field.name, nullable=not field.required)

    def construct_date(self, field):
        return Date(name=field.name, nullable=not field.required,
            minimum=field.minimum, maximum=field.maximum)

    def construct_datetime(self, field):
        return DateTime(name=field.name, nullable=not field.required,
            minimum=field.minimum, maximum=field.maximum,
            timezone=True)

    def construct_decimal(self, field):
        return Decimal(name=field.name, nullable=not field.required,
            minimum=field.minimum, maximum=field.maximum)

    def construct_definition(self, field):
        return Definition(name=field.name, nullable=not field.required)

    def construct_enumeration(self, field):
        return Enumeration(name=field.name, nullable=not field.required,
            enumeration=field.enumeration)

    def construct_float(self, field):
        return Float(name=field.name, nullable=not field.required,
            minimum=field.minimum, maximum=field.maximum)

    def construct_integer(self, field):
        return Integer(name=field.name, nullable=not field.required,
            minimum=field.minimum, maximum=field.maximum)

    def construct_map(self, field):
        if self.use_json_for_map:
            return Json(name=field.name, nullable=not field.required)
        else:
            raise ValueError(field)

    def construct_object(self, field):
        raise ValueError(field)

    def construct_sequence(self, field):
        equivalent = EQUIVALENTS.get(field.item.basetype)
        if not equivalent:
            raise ValueError(field)

        return Array(name=field.name, nullable=not field.required,
            item_type=equivalent)

    def construct_structure(self, field):
        if self.use_json_for_structure:
            return Json(name=field.name, nullable=not field.required)
        else:
            raise ValueError(field)

    def construct_surrogate(self, field):
        return Surrogate(name=field.name, nullable=not field.required)

    def construct_text(self, field):
        return Text(name=field.name, nullable=not field.required,
            min_length=field.min_length, max_length=field.max_length)

    def construct_time(self, field):
        return Time(name=field.name, nullable=not field.required,
            minimum=field.minimum, maximum=field.maximum)
