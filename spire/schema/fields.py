import json
import re

from sqlalchemy import Column, ForeignKey as _ForeignKey, types
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.ext.mutable import Mutable
from sqlalchemy.types import TypeDecorator, UserDefinedType

from spire.util import uniqid

__all__ = ('Array', 'ArrayType', 'BigInteger', 'BigIntegerType', 'Boolean',
    'BooleanType', 'Date', 'DateType', 'DateTime', 'DateTimeType', 'Decimal',
    'DecimalType', 'Email', 'EmailType', 'Enumeration', 'EnumerationType',
    'Float', 'FloatType', 'ForeignKey', 'Hstore', 'HstoreType', 'Identifier',
    'Integer', 'IntegerType', 'Json', 'JsonType', 'Serialized',
    'SerializedType', 'Text', 'TextType', 'Time', 'TimeType', 'Token',
    'TokenType', 'UUID', 'UUIDType')

class TypeDecorator(TypeDecorator):
    def __repr__(self):
        return '%s()' % type(self).__name__

class MutableDict(Mutable, dict):
    @classmethod
    def coerce(cls, key, value):
        if isinstance(value, MutableDict):
            return value
        elif isinstance(value, dict):
            return MutableDict(value)
        else:
            return Mutable.coerce(key, value)

    def __delitem__(self, key):
        dict.__delitem__(self, key)
        self.changed()

    def __setitem__(self, key, value):
        dict.__setitem__(self, key, value)
        self.changed()

class ValidatesMinMax(object):
    def validate(self, instance, column, value):
        minimum = self.minimum
        if minimum is not None and value < minimum:
            raise ValueError('%r is less then %r (minimum)' % (value, minimum))

        maximum = self.maximum
        if maximum is not None and value > maximum:
            raise ValueError('%r is greater then %r (maximum)' % (value, maximum))

ArrayType = ARRAY
BooleanType = types.Boolean

class BigIntegerType(TypeDecorator, ValidatesMinMax):
    impl = types.BigInteger

    def __init__(self, minimum=None, maximum=None):
        super(BigIntegerType, self).__init__()
        self.minimum = minimum
        self.maximum = maximum

class DateType(TypeDecorator, ValidatesMinMax):
    impl = types.Date

    def __init__(self, minimum=None, maximum=None):
        super(DateType, self).__init__()
        self.minimum = minimum
        self.maximum = maximum

class DateTimeType(TypeDecorator, ValidatesMinMax):
    impl = types.DateTime

    def __init__(self, minimum=None, maximum=None, timezone=False):
        super(DateTimeType, self).__init__(timezone=timezone)
        self.minimum = minimum
        self.maximum = maximum

class DecimalType(TypeDecorator, ValidatesMinMax):
    impl = types.Numeric

    def __init__(self, minimum=None, maximum=None, precision=None, scale=None):
        super(DecimalType, self).__init__(precision=precision, scale=scale)
        self.minimum = minimum
        self.maximum = maximum

class EnumerationType(TypeDecorator):
    impl = types.Text

    def __init__(self, enumeration=None):
        super(EnumerationType, self).__init__()
        if enumeration is not None:
            if isinstance(enumeration, basestring):
                enumeration = enumeration.split(' ')
            self.enumeration = enumeration

    def validate(self, instance, column, value):
        if not self.enumeration:
            return

        if value in self.enumeration:
            return value
        else:
            raise ValueError('%r is not a valid value for this enumeration' % value)

class FloatType(TypeDecorator, ValidatesMinMax):
    impl = types.Float

    def __init__(self, minimum=None, maximum=None):
        super(FloatType, self).__init__()
        self.minimum = minimum
        self.maximum = maximum

class HstoreType(UserDefinedType):
    def get_col_spec(self):
        return 'hstore'

class IntegerType(TypeDecorator, ValidatesMinMax):
    impl = types.Integer

    def __init__(self, minimum=None, maximum=None):
        super(IntegerType, self).__init__()
        self.minimum = minimum
        self.maximum = maximum

class JsonType(TypeDecorator):
    impl = types.Text

    def process_bind_param(self, value, dialect):
        if value is not None:
            return json.dumps(value, sort_keys=True)

    def process_result_value(self, value, dialect):
        if value is not None:
            return json.loads(value)

class SerializedType(TypeDecorator):
    impl = types.Text

    def process_bind_param(self, value, dialect):
        if value is not None:
            return json.dumps(value, sort_keys=True)

    def process_result_value(self, value, dialect):
        if value is not None:
            return json.loads(value)

class TextType(TypeDecorator):
    impl = types.Text
    pattern = None

    def __init__(self, pattern=None, min_length=None, max_length=None):
        super(TextType, self).__init__()
        self.min_length = min_length
        self.max_length = max_length
        if pattern:
            self.pattern = pattern

    def validate(self, instance, column, value):
        if self.pattern and not self.pattern.match(value):
            raise ValueError('%r does not match the pattern for this field' % value)

        min_length = self.min_length
        if min_length is not None and len(value) < min_length:
            raise ValueError('value is too short')

        max_length = self.max_length
        if max_length is not None and len(value) > max_length:
            raise ValueError('value is too long')

class TimeType(TypeDecorator, ValidatesMinMax):
    impl = types.Time

    def __init__(self, minimum=None, maximum=None):
        super(TimeType, self).__init__()
        self.minimum = minimum
        self.maximum = maximum

class TokenType(TypeDecorator):
    impl = types.Text
    pattern = re.compile(r'^\w[-+.\w]*(?<=\w)(?::\w[-+.\w]*(?<=\w))*$')

    def __init__(self, segments=None):
        super(TokenType, self).__init__()
        self.segments = segments

    def validate(self, instance, column, value):
        if not self.pattern.match(value):
            raise ValueError('%r is not a valid token' % value)

        segments = self.segments
        if segments is not None and value.count(':') + 1 != segments:
            raise ValueError('%r does not have exactly %r segments' % (value, segments))

class EmailType(TextType):
    pattern = re.compile(
        r"(?i)^([-!#$%&'*+/=?^_`{}|~0-9A-Z]+(\.[-!#$%&'*+/=?^_`{}|~0-9A-Z]+)*"
        r'|"([\001-\010\013\014\016-\037!#-\[\]-\177]|\\[\001-\011\013\014\016-\177])*"'
        r')@(?:[A-Z0-9-]+\.)+[A-Z]{2,6}')

class IPAddressType(TextType):
    pattern = re.compile(r'^\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}$')

class UUIDType(TextType):
    pattern = re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$')

def Array(item_type, as_tuple=False, **params):
    return Column(ArrayType(item_type, as_tuple=as_tuple), **params)

def BigInteger(minimum=None, maximum=None, **params):
    return Column(BigIntegerType(minimum, maximum), **params)

def Boolean(nullable=False, **params):
    return Column(BooleanType(), nullable=nullable, **params)

def Date(minimum=None, maximum=None, **params):
    return Column(DateType(minimum, maximum), **params)

def DateTime(minimum=None, maximum=None, timezone=None, **params):
    return Column(DateTimeType(minimum, maximum, timezone), **params)

def Decimal(minimum=None, maximum=None, precision=None, scale=None, **params):
    return Column(DecimalType(minimum, maximum, precision, scale), **params)

def Email(**params):
    return Column(EmailType(), **params)

def Enumeration(enumeration, **params):
    return Column(EnumerationType(enumeration), **params)

def Float(minimum=None, maximum=None, **params):
    return Column(FloatType(minimum, maximum), **params)

def ForeignKey(column, **params):
    column_params = {}
    for name in ('name', 'type_', 'default', 'doc', 'index', 'info', 'nullable', 'unique', 'primary_key'):
        if name in params:
            column_params[name] = params.pop(name)

    return Column(_ForeignKey(column, **params), **column_params)

def Hstore(**params):
    return Column(HstoreType(), **params)

def Identifier(**params):
    return Column(UUIDType(), nullable=False, primary_key=True, default=uniqid, **params)

def Integer(minimum=None, maximum=None, **params):
    return Column(IntegerType(minimum, maximum), **params)

def Json(**params):
    return Column(JsonType(), **params)

def Serialized(**params):
    return Column(SerializedType(), **params)

def Text(pattern=None, min_length=None, max_length=None, **params):
    return Column(TextType(pattern, min_length, max_length), **params)

def Time(minimum=None, maximum=None, **params):
    return Column(TimeType(minimum, maximum), **params)

def Token(segments=None, **params):
    return Column(TokenType(segments), **params)

def UUID(**params):
    return Column(UUIDType(), **params)
