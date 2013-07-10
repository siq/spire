from glob import glob
from threading import Lock
from time import sleep

from mesh.exceptions import ConnectionFailed
from mesh.transport.http import Connection
from scheme import *

from spire.core import Assembly
from spire.exceptions import TemporaryStartupError
from spire.runtime.registration import ServiceEndpoint
from spire.support.logs import LogHelper, configure_logging
from spire.util import (enumerate_tagged_methods, find_tagged_method,
    recursive_merge, topological_sort)

COMPONENTS_SCHEMA = Sequence(Object(name='component', nonnull=True),
    name='components', unique=True)

PARAMETERS_SCHEMA = Structure({
    'name': Text(),
    'registration_url': Text(),
    'services': Sequence(Structure({
        'id': Token(segments=1, nonempty=True),
        'enabled': Boolean(default=True),
        'dependencies': Sequence(Token(segments=1, nonempty=True), unique=True),
        'required': Boolean(default=True),
    }, nonnull=True), nonnull=True),
    'startup_attempts': Integer(default=12),
    'startup_enabled': Boolean(default=True),
    'startup_timeout': Integer(default=5),
}, name='parameters')

log = LogHelper('spire.runtime')

class Runtime(object):
    """A spire runtime."""

    guard = Lock()
    runtime = None

    def __new__(cls, *args, **params):
        with Runtime.guard:
            Runtime.runtime = super(Runtime, cls).__new__(cls, *args, **params)
            return Runtime.runtime

    def __init__(self, configuration=None, assembly=None):
        self.assembly = assembly or Assembly.current()
        self.components = {}
        self.configuration = {}
        self.parameters = {}
        self.services = {}

        if configuration:
            self.configure(configuration)

    @property
    def host(self):
        raise NotImplementedError()

    @property
    def pid(self):
        raise NotImplementedError()

    def configure(self, configuration):
        if isinstance(configuration, basestring):
            configuration = Format.read(configuration, quiet=True)
            if not configuration:
                return

        includes = configuration.pop('include', None)
        recursive_merge(self.configuration, configuration)

        if includes:
            for pattern in includes:
                for include in sorted(glob(pattern)):
                    self.configure(include)

        return self

    def deploy(self):
        configuration = self.configuration
        if 'logging' in configuration:
            configure_logging(configuration['logging'])

        parameters = configuration.get('spire') or {}
        self.parameters = PARAMETERS_SCHEMA.process(parameters)

        components = configuration.get('components')
        if components:
            components = COMPONENTS_SCHEMA.process(components, serialized=True)

        config = configuration.get('configuration')
        if config:
            self.assembly.configure(config)

        for component in components:
            self.components[component.identity] = self.assembly.instantiate(component)

        return self

    def lock(self):
        pass

    def reload(self):
        pass

    def startup(self):
        if not self.parameters['startup_enabled']:
            log('warning', 'skipping startup of components')
            return

        attempts = self.parameters['startup_attempts']
        timeout = self.parameters['startup_timeout']

        for component in self.components.itervalues():
            methods = enumerate_tagged_methods(component, 'onstartup', True)
            if methods:
                log('info', 'initiating startup of %s', component.identity)
                for method in self._sort_methods(methods):
                    self._execute_startup_method(component, method, attempts, timeout)
                log('info', 'finished startup of %s', component.identity)

    def unlock(self):
        pass

    def _execute_service_startup(self, service, stage=None):
        for component in self.components.itervalues():
            method = find_tagged_method(component, onstartup=True, service=service, stage=stage)
            if method:
                break
        else:
            return {'status': 'ready'}

        try:
            response = method()
            if response:
                return response
            else:
                return {'status': 'ready'}
        except Exception:
            log('exception', 'execution of %s for startup of service %s at stage %s'
                ' raised exception' % (method.__name__, service, stage))
            raise

    def _execute_startup_method(self, component, method, attempts, timeout):
        params = (method.__name__, component.identity)
        log('info', 'executing %s for startup of %s' % params)

        for _ in range(attempts - 1):
            try:
                method()
            except TemporaryStartupError:
                log('warning', 'execution of %s for startup of %s delayed' % params)
                sleep(timeout)
            except Exception:
                log('exception', 'execution of %s for startup of %s raised exception' % params)
                break
            else:
                log('info', 'execution of %s for startup of %s completed' % params)
                break
        else:
            log('error', 'execution of %s for startup of %s timed out' % params)

    def _register_services(self, dispatcher):
        url = self.parameters.get('registration_url')
        if not url:
            return

        services = self.parameters.get('services')
        if not services:
            return

        for service in services:
            if service.get('enabled', True):
                break
        else:
            return

        connection = Connection(url)
        for _ in range(10):
            try:
                connection.request('GET')
            except (ConnectionFailed, IOError):
                sleep(3)
            else:
                break
        else:
            raise Exception('failed to register services')

        host = self.host
        for service in services:
            if service.get('enabled', True):
                path = '/spire.service/%s' % service['id']
                dispatcher.mount(ServiceEndpoint(self, service, path=path,
                    shared_path='/spire.service'))

                body = {'id': service['id'], 'pid': self.pid, 'required': service['required'],
                    'endpoint': 'http://%s%s' % (host, path)}
                if 'dependencies' in service:
                    body['dependencies'] = service['dependencies']

                connection.request('POST', body=body, mimetype='application/json',
                    serialize=True)

    def _sort_methods(self, candidates):
        methods = {}
        for method in candidates:
            if method.service is None:
                methods[method.__name__] = method

        graph = {}
        for method in methods.itervalues():
            edges = set()
            for name in method.after:
                if name in methods:
                    edges.add(methods[name])
            graph[method] = edges

        return topological_sort(graph)

def current_runtime():
    return Runtime.runtime

def onstartup(after=None, service=None, stage=None):
    if isinstance(after, basestring):
        after = after.split(' ') if after else None
    if not after:
        after = []

    def decorator(method):
        method.after = after
        method.onstartup = True
        method.service = service
        method.stage = stage
        return method
    return decorator
