from threading import Lock

from sqlalchemy import Column, MetaData, Table, event
from sqlalchemy.ext.declarative import DeclarativeMeta, declarative_base
from sqlalchemy.orm import mapper
from sqlalchemy.orm.attributes import InstrumentedAttribute
from sqlalchemy.orm.mapper import Mapper
from sqlalchemy.orm.properties import ColumnProperty
from sqlalchemy.orm.session import object_session

from spire.schema.schema import Schema, SessionLocals
from spire.util import get_constructor_args, pluralize

__all__ = ('Model',)

MAPPER_PARAMS = get_constructor_args(Mapper)

class AttributeValidator(object):
    def __init__(self, column):
        self.column = column

    def __call__(self, instance, value, oldvalue, initiator):
        column = self.column
        if value is None:
            if column.nullable:
                return value
            else:
                raise ValueError(repr(self.column))
        else:
            return column.type.validate(instance, column, value) or value

    @staticmethod
    def _attach_validators(mapper, cls):
        for column_property in mapper.iterate_properties:
            if isinstance(column_property, ColumnProperty) and len(column_property.columns) == 1:
                column = column_property.columns[0]
                if hasattr(column.type, 'validate'):
                    event.listen(column_property.class_attribute, 'set',
                        AttributeValidator(column), retval=True)

class ModelMeta(DeclarativeMeta):
    def __new__(metatype, name, bases, namespace):
        meta = namespace.pop('meta', None)
        if not meta:
            return DeclarativeMeta.__new__(metatype, name, bases, namespace)
        elif not isinstance(meta, dict):
            meta = dict(meta.__dict__)

        schema = meta.pop('schema')
        if not isinstance(schema, Schema):
            schema = Schema(schema)

        namespace['_spire_schema'] = schema
        namespace['metadata'] = schema.metadata

        abstract = meta.pop('abstract', False)
        tablename = meta.pop('tablename', None)

        mapper_params = {}
        for param in MAPPER_PARAMS:
            if param in meta:
                mapper_params[param] = meta.pop(param)

        if mapper_params:
            namespace['__mapper_args__'] = mapper_params

        table_args = []
        for param in ('constraints', 'indexes'):
            if param in meta:
                table_args.extend(meta.pop(param))

        if meta:
            meta = dict((key, value) for key, value in meta.iteritems() if key[0] != '_')
            if meta:
                table_args.append(meta)

        if table_args:
            namespace['__table_args__'] = tuple(table_args)

        if not tablename:
            tablename = name.lower()
        if '__tablename__' not in namespace and not abstract:
            namespace['__tablename__'] = tablename

        model = DeclarativeMeta.__new__(metatype, name, bases, namespace)
        return model

    def __call__(cls, *args, **params):
        instance = super(ModelMeta, cls).__call__(*args, **params)
        for column in instance.__table__.columns:
            default = column.default
            if default and getattr(instance, column.name) is None:
                if default.is_scalar:
                    setattr(instance, column.name, default.arg)
                elif default.is_callable:
                    setattr(instance, column.name, default.arg(None))

        return instance

class ModelBase(object):
    def __init__(self, **params):
        cls = type(self)
        for attr, value in params.iteritems():
            definition = getattr(cls, attr, None)
            if isinstance(definition, InstrumentedAttribute):
                setattr(self, attr, value)

    def __repr__(self):
        try:
            return "%s('%s')" % (type(self).__name__, unicode(self))
        except TypeError:
            return super(ModelBase, self).__repr__()

    def __unicode__(self):
        try:
            return str(self.id)
        except AttributeError:
            return id(self)

    @property
    def session(self):
        return object_session(self)

    def extract_dict(self, attrs=None, exclude=None, drop_none=False, **extraction):
        if not attrs:
            attrs = [column.name for column in self.__mapper__.columns]
        if isinstance(attrs, (tuple, list)):
            attrs = dict(zip(attrs, attrs))

        if exclude:
            if isinstance(exclude, basestring):
                exclude = exclude.split(' ')
            for attr in exclude:
                attrs.pop(attr, None)

        for attr, name in attrs.iteritems():
            value = getattr(self, attr)
            if not (drop_none and value is None):
                extraction[name] = value
        
        return extraction

    @classmethod
    def load(cls, session, lockmode=None, **filters):
        query = session.query(cls).filter_by(**filters)
        if lockmode:
            query = query.with_lockmode(lockmode)
        return query.one()

    @classmethod
    def polymorphic_create(cls, data):
        column = cls.__mapper__.polymorphic_on
        if column is None or cls.__mapper__.polymorphic_identity:
            return cls(**data)

        identity = data.get(column.name)
        if not identity:
            raise ValueError(data)

        mapper = cls.__mapper__.polymorphic_map.get(identity)
        if mapper:
            return mapper.class_(**data)
        else:
            raise ValueError(identity)

    def update_with_mapping(self, mapping=None, attrs=None, ignore=None, **params):
        if isinstance(attrs, basestring):
            attrs = attrs.split(' ')
        if isinstance(ignore, basestring):
            ignore = ignore.split(' ')

        if mapping:
            for attr, value in mapping.iteritems():
                if attr not in params:
                    params[attr] = value

        cls = type(self)
        for attr, value in params.iteritems():
            if ignore and attr in ignore:
                continue
            if attrs and attr not in attrs:
                continue
            if isinstance(getattr(cls, attr, None), InstrumentedAttribute):
                setattr(self, attr, value)

        return self

Model = declarative_base(cls=ModelBase, constructor=None, name='Model', metaclass=ModelMeta)
event.listen(mapper, 'mapper_configured', AttributeValidator._attach_validators)
