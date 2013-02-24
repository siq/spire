from mesh.constants import OK, RETURNING
from mesh.exceptions import GoneError, NotFoundError
from mesh.standard import Controller
from sqlalchemy.sql import asc, column, desc, func, literal_column, not_, select

from spire.core import Unit
from spire.schema import NoResultFound

__all__ = ('ModelController', 'ProxyController', 'support_returning')

EMPTY = []

class FieldFilter(object):
    def __init__(self, controller, data):
        if not data:
            self.fields = controller.default_fields
            return
        if 'fields' in data:
            self.fields = set(data['fields'])
            return

        self.fields = controller.default_fields.copy()
        if 'include' in data:
            self.fields.update(data['include'])
        if 'exclude' in data:
            self.fields.difference_update(data['exclude'])

    def __contains__(self, field):
        return (field in self.fields)

class FilterOperators(object):
    def equal_op(self, query, column, value):
        return query.filter(column == value)

    def iequal_op(self, query, column, value):
        return query.filter(func.lower(column) == value)

    def not_op(self, query, column, value):
        return query.filter(column != value)

    def inot_op(self, query, column, value):
        return query.filter(func.lower(column) != value)

    def prefix_op(self, query, column, value):
        return query.filter(column.like(value + '%'))

    def iprefix_op(self, query, column, value):
        return query.filter(column.ilike(value + '%'))

    def suffix_op(self, query, column, value):
        return query.filter(column.like('%' + value))

    def isuffix_op(self, query, column, value):
        return query.filter(column.ilike('%' + value))

    def contains_op(self, query, column, value):
        return query.filter(column.like('%' + value + '%'))

    def icontains_op(self, query, column, value):
        return query.filter(column.ilike('%' + value + '%'))

    def gt_op(self, query, column, value):
        return query.filter(column > value)

    def gte_op(self, query, column, value):
        return query.filter(column >= value)

    def lt_op(self, query, column, value):
        return query.filter(column < value)

    def lte_op(self, query, column, value):
        return query.filter(column <= value)

    def null_op(self, query, column, value):
        if value:
            return query.filter(column == None)
        else:
            return query.filter(column != None)

    def in_op(self, query, column, value):
        return query.filter(column.in_(value))

    def notin_op(self, query, column, value):
        return query.filter(not_(column.in_(value)))

def parse_attr_mapping(mapping):
    if isinstance(mapping, basestring):
        mapping = mapping.split(' ')
    if isinstance(mapping, (list, tuple)):
        pairs = {}
        for pair in mapping:
            if isinstance(pair, (list, tuple)):
                pairs[pair[0]] = pair[1]
            else:
                pairs[pair] = pair
        mapping = pairs
    return mapping

class ModelController(Unit, Controller):
    """A mesh controller for spire.schema models."""

    default_fields = None
    schema = None
    mapping = None
    model = None
    polymorphic_mapping = None
    polymorphic_on = None
    operators = FilterOperators()

    @classmethod
    def __construct__(cls):
        Controller.__construct__()
        if cls.resource:
            cls._composite_key = cls.resource.composite_key
            cls._id_field = cls.resource.id_field.name

            cls.default_fields = set()
            for name, field in cls.resource.schema.iteritems():
                if field.is_identifier or not field.deferred:
                    cls.default_fields.add(name)

            attr = cls.polymorphic_on
            if attr and not isinstance(attr, tuple):
                cls.polymorphic_on = (attr, attr)

            mapping = cls.polymorphic_mapping
            if mapping:
                for identity, submapping in mapping.items():
                    mapping[identity] = parse_attr_mapping(submapping)
            else:
                mapping = cls.mapping
                if mapping is None:
                    mapping = cls.resource.filter_schema().keys()
                cls.mapping = parse_attr_mapping(mapping)

    def acquire(self, subject):
        if self._composite_key:
            try:
                subject = subject.split(';')
            except Exception:
                return None

        try:
            return self.schema.session.query(self.model).get(subject)
        except NoResultFound:
            return None

    def create(self, request, response, subject, data):
        returning = data.pop(RETURNING, None)
        instance = self.model.polymorphic_create(self._construct_model(data))

        self._annotate_model(request, instance, data)
        self.schema.session.add(instance)

        self.schema.session.commit()
        response(self._construct_returning(instance, returning))

    def delete(self, request, response, subject, data):
        subject.session.delete(subject)
        subject.session.commit()
        response({'id': self._get_id_value(subject)})

    def get(self, request, response, subject, data):
        response(self._construct_resource(request, subject, data))

    def load(self, request, response, subject, data):
        candidates = data['identifiers']
        if not candidates:
            return response([])

        identifiers = []
        for i, identifier in enumerate(candidates):
            identifiers.append("(%d, '%s')" % (i, str(identifier)))

        expr = select([column('rank'), column('id')],
            from_obj="(values %s) as subset(rank, id)" % ', '.join(identifiers))

        query = (self.schema.session.query(self.model)
            .join(expr.cte('__subset__'), literal_column('__subset__.id')==self.model.id)
            .order_by(literal_column('__subset__.rank')))

        resources = []
        instances = list(query.all())

        instance = (instances.pop(0) if instances else None)
        for id in candidates:
            if instance:
                if instance.id == id:
                    resources.append(self._construct_resource(request, instance, data))
                    if instances:
                        instance = instances.pop(0)
                    else:
                        instance = None
                else:
                    resources.append(None)
            else:
                resources.append(None)

        response(resources)

    def put(self, request, response, subject, data):
        if subject:
            self.update(request, response, subject, data)
        else:
            data['id'] = request.subject
            self.create(request, response, subject, data)

    def query(self, request, response, subject, data):
        data = data or {}
        query = self.schema.session.query(self.model)

        filters = data.get('query')
        if filters:
            query = self._construct_filters(query, filters)

        query = self._annotate_query(request, query, data)

        total = query.count()
        if data.get('total'):
            return response({'total': total})

        if 'sort' in data:
            query = self._construct_sorting(query, data['sort'])
        if 'limit' in data:
            query = query.limit(data['limit'])
        if 'offset' in data:
            query = query.offset(data['offset'])

        resources = []
        for instance in query.all():
            resources.append(self._construct_resource(request, instance, data))

        response({'total': total, 'resources': resources})

    def update(self, request, response, subject, data):
        returning = data.pop(RETURNING, None)
        if data:
            subject.update_with_mapping(self._construct_model(data))
            self._annotate_model(request, subject, data)
            subject.session.commit()

        response(self._construct_returning(subject, returning))

    def _annotate_filter(self, query, filter, value):
        pass

    def _annotate_model(self, request, model, data):
        pass

    def _annotate_resource(self, request, model, resource, data):
        pass

    def _annotate_query(self, request, query, data):
        return query

    def _construct_filters(self, query, filters):
        model = self.model
        mapping = self._get_mapping(model)
        operators = self.operators

        for filter, value in filters.iteritems():
            annotation = self._annotate_filter(query, filter, value)
            if annotation:
                query = annotation
                continue

            attr, operator = filter, 'equal'
            if '__' in filter:
                attr, operator = filter.rsplit('__', 1)

            column = getattr(model, mapping[attr])
            if not column:
                continue

            constructor = getattr(operators, operator + '_op')
            query = constructor(query, column, value)

        return query

    def _construct_model(self, data):
        mapping = self.mapping
        if self.polymorphic_on:
            mapping = self.polymorphic_mapping[data[self.polymorphic_on[0]]]

        model = {}
        for name, attr in mapping.iteritems():
            if name in data:
                model[attr] = data[name]
        
        if self._composite_key and 'id' in model:
            del model['id']
        return model

    def _construct_resource(self, request, model, data, **resource):
        mapping = self._get_mapping(model)
        fields = FieldFilter(self, data)

        resource['id'] = self._get_id_value(model)
        for name, attr in mapping.iteritems():
            if name in fields and name != 'id':
                try:
                    resource[name] = getattr(model, attr)
                except AttributeError:
                    pass

        self._annotate_resource(request, model, resource, data)
        return resource

    def _construct_returning(self, model, returning, response=None):
        if response is None:
            response = {}
        if 'id' not in response:
            response['id'] = self._get_id_value(model)

        if returning:
            mapping = self._get_mapping(model)
            for name in returning:
                if name in mapping and name not in response:
                    try:
                        response[name] = getattr(model, mapping[name])
                    except AttributeError:
                        pass
        return response

    def _construct_sorting(self, query, sorting):
        model = self.model
        mapping = self._get_mapping(model)

        columns = []
        for attr in sorting:
            direction = asc
            if attr[-1] == '+':
                attr = attr[:-1]
            elif attr[-1] == '-':
                attr = attr[:-1]
                direction = desc

            column = getattr(model, mapping[attr])
            if not column:
                continue

            columns.append(direction(column))

        return query.order_by(*columns)

    def _get_id_value(self, model):
        mapping = self._get_mapping(model)
        if self._composite_key:
            values = []
            for key in self._composite_key:
                values.append(getattr(model, mapping[key]))
            return ';'.join(values)
        else:
            return getattr(model, mapping['id'])

    def _get_mapping(self, model):
        if self.polymorphic_on:
            identity = getattr(model, self.polymorphic_on[1])
            return self.polymorphic_mapping[identity]
        else:
            return self.mapping

def support_returning(method):
    def wrapper(self, request, response, subject, data):
        returning = data.pop(RETURNING, None)
        model = method(self, request, response, subject, data)
        response(self._construct_returning(model, returning))
    return wrapper

class ProxyController(Unit, Controller):
    """A mesh controller for mesh proxy models."""
    proxy_model = None
    mapping = None

    @classmethod
    def __construct__(cls):
        Controller.__construct__()
        if cls.resource:
            mapping = cls.mapping
            if mapping is None:
                mapping = cls.resource.filter_schema.keys()
            cls.mapping = parse_attr_mapping(mapping)

            cls.id_field = cls.resource.id_field

    def acquire(self, subject):
        try:
            return self.proxy_model.get(subject)
        except GoneError:
            return None

    def create(self, request, response, subject, data):
        proxy_model = self._construct_proxy_model(data)
        self._annotate_proxy_model(request, proxy_model, data)
        subject = self.proxy_model.create(proxy_model)
        id_field = self.id_field
        response({id_field: self._get_proxy_model_value(subject, id_field)})

    def delete(self, request, response, subject, data):
        subject.destroy()
        id_field = self.id_field
        response({id_field: self._get_proxy_model_value(subject, id_field)})

    def get(self, request, response, subject, data):
        resource = self._construct_resource(request, subject, data)
        self._annotate_resource(request, resource, subject, data)
        response(self._prune_resource(resource, data))

    def put(self, request, response, subject, data):
        if subject:
            self.update(request, response, subject, data)
        else:
            data[self.id_field] = request.subject
            self.create(request, response, subject, data)

    def query(self, request, response, subject, data):
        data = data or {}
        if 'query' in data:
            data['query'] = self._construct_filter(data['query'])

        try:
            query_results = self.proxy_model.query(**data).all()
        except NotFoundError:
            query_results = []
            total = 0
            status = OK
        else:
            total = query_results.total
            status = query_results.status

        resources = []
        for result in query_results:
            resource = self._construct_resource(request, result, data)
            self._annotate_resource(request, resource, result, data)
            resources.append(self._prune_resource(resource, data))

        response(status=status, 
                 content={'resources': resources, 'total': total})

    def update(self, request, response, subject, data):
        if data:
            proxy_data = self._construct_proxy_model(data)
            self._annotate_proxy_model(request, proxy_data, data)
            subject.update(proxy_data)
        id_field = self.id_field
        response({id_field: self._get_proxy_model_value(subject, id_field)})

    def _construct_filter(self, filters):
        mapping = self.mapping
        subject_filters = {}
        for filter_operand, value in filters.iteritems():
            filter_operands = filter_operand.rsplit('__', 1)
            filter_operands[0] = mapping[filter_operands[0]]
            subject_filters['__'.join(filter_operands)] = value

        return subject_filters

    def _construct_resource(self, request, subject, data):
        resource = {}
        for res_field, proxy_field in self.mapping.iteritems():
            try:
                resource[res_field] = getattr(subject, proxy_field)
            except AttributeError:
                continue
        return resource

    def _construct_proxy_model(self, data):
        subject = {}
        mapping = self.mapping
        for field, value in data.iteritems():
            subject_field = mapping[field]
            subject[subject_field] = value
        return subject

    def _get_proxy_model_value(self, subject, field):
        model_field = self.mapping[field]
        return getattr(subject, model_field)

    def _annotate_resource(self, request, resource, proxy_model, data):
        pass

    def _annotate_proxy_model(self, request, proxy_data, data):
        pass
