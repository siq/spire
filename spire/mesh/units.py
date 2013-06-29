from __future__ import absolute_import
import json

from mesh.binding.python import bind
from mesh.transport.http import HttpClient, HttpProxy, HttpServer
from scheme import *
from scheme.supplemental import ObjectReference
from scheme.surrogate import surrogate

from spire.core import *
from spire.context import ContextMiddleware, HeaderParser
from spire.local import ContextLocals
from spire.schema.fields import Column, TypeDecorator, types
from spire.wsgi.application import Request
from spire.wsgi.util import Mount

__all__ = ('Definition', 'DefinitionType', 'ExplicitContextManager', 'MeshClient',
    'MeshProxy', 'MeshDependency', 'MeshServer', 'Surrogate', 'SurrogateType')

CONTEXT_HEADER_PREFIX = 'X-SPIRE-'
ContextLocal = ContextLocals.declare('mesh.context')

class DefinitionType(TypeDecorator):
    impl = types.Text

    def process_bind_param(self, value, dialect):
        if value is not None:
            return json.dumps(value.describe(), sort_keys=True)

    def process_result_value(self, value, dialect):
        if value is not None:
            return Field.reconstruct(json.loads(value))

def Definition(**params):
    return Column(DefinitionType(), **params)

class SurrogateType(TypeDecorator):
    impl = types.Text

    def process_bind_param(self, value, dialect):
        if value is not None:
            return json.dumps(value.serialize(), sort_keys=True)

    def process_result_value(self, value, dialect):
        if value is not None:
            return surrogate.unserialize(json.loads(value))

def Surrogate(**params):
    return Column(SurrogateType(), **params)

def get_mesh_context():
    context = ContextLocal.get()
    if context:
        return context

    request = Request.current_request()
    if request:
        return request.context

def construct_mesh_client(url, specification=None, timeout=None, client=HttpClient, bundle=None):
    return client(url, specification, get_mesh_context, timeout=timeout, bundle=bundle,
        context_header_prefix=CONTEXT_HEADER_PREFIX)

class MeshClient(Unit):
    configuration = Configuration({
        'bundle': ObjectReference(nonnull=True),
        'client': ObjectReference(nonnull=True, required=True, default=HttpClient),
        'introspect': Boolean(default=False),
        'name': Text(nonempty=True),
        'specification': ObjectReference(nonnull=True),
        'timeout': Integer(default=180),
        'url': Text(nonempty=True),
    })

    name = configured_property('name')
    url = configured_property('url')

    def __init__(self, client, url, timeout):
        specification = self.configuration.get('specification')
        if not specification:
            bundle = self.configuration.get('bundle')
            if bundle:
                specification = bundle.specify()
        if not specification and not self.configuration.get('introspect'):
            raise Exception()

        self.cache = {}
        self.instance = construct_mesh_client(url, specification, timeout, client, self.name)
        self.instance.register()

    def bind(self, name, mixin_modules=None):
        try:
            return self.cache[name]
        except KeyError:
            self.cache[name] = bind(self.instance.specification, name, mixin_modules)
            return self.cache[name]

    def construct_url(self, path=None):
        url = self.url
        if path:
            url = '%s/%s' % (url.rstrip('/'), path.lstrip('/'))
        return url

    def execute(self, *args, **params):
        return self.instance.execute(*args, **params)

    def prepare(self, *args, **params):
        return self.instance.prepare(*args, **params)

    def ping(self):
        return self.instance.ping()

class MeshProxy(Mount):
    configuration = Configuration({
        'timeout': Integer(default=120),
        'url': Text(nonempty=True),
    })

    url = configured_property('url')

    def __init__(self, url, timeout):
        self.application = HttpProxy(url, self._construct_context, context_key='request.context',
            context_header_prefix=CONTEXT_HEADER_PREFIX, timeout=timeout)
        super(MeshProxy, self).__init__()

    def _construct_context(self):
        request = Request.current_request()
        if request:
            return request.context

class MeshDependency(Dependency):
    def __init__(self, name, proxy=False, optional=False, deferred=False,
            unit=None, **params):

        self.name = name
        if proxy:
            token = 'mesh-proxy:%s' % name
            unit = unit or MeshProxy
        else:
            token = 'mesh:%s' % name
            unit = unit or MeshClient

        super(MeshDependency, self).__init__(unit, token, optional, deferred, **params)

    def contribute_params(self):
        return {'name': self.name}

class MeshServer(Mount):
    configuration = Configuration({
        'bundles': Sequence(ObjectReference(notnull=True), required=True, unique=True),
        'mediators': Sequence(Text(nonempty=True), nonnull=True, unique=True),
        'server': ObjectReference(nonnull=True, default=HttpServer),
    })

    def __init__(self, bundles, server, mediators=None):
        self.mediators = []
        if mediators:
            for mediator in mediators:
                self.mediators.append(getattr(self, mediator))

        super(MeshServer, self).__init__()
        self.server = server(bundles, mediators=self.mediators, context_key='request.context')

    def dispatch(self, environ, start_response):
        ContextLocal.push(environ.get('request.context'))
        try:
            return self.server(environ, start_response)
        finally:
            ContextLocal.pop()

class ContextLocalManager(object):
    def __init__(self, context):
        self.context = context

    def __enter__(self):
        ContextLocal.push(self.context)

    def __exit__(self, *args):
        ContextLocal.pop()

class ExplicitContextManager(object):
    def __call__(self):
        context = ContextLocal.get()
        if context:
            return context

    def set(self, context):
        return ContextLocalManager(context)
