from scheme import Boolean, Sequence, Text
from werkzeug.exceptions import BadRequest, HTTPException, InternalServerError, NotFound
from werkzeug.wrappers import Request, Response

from spire.core import Configuration, Unit
from spire.local import ContextLocals
from spire.support.logs import LogHelper

log = LogHelper('spire.wsgi')

class Mount(Unit):
    configuration = Configuration({
        'middleware': Sequence(Text(nonempty=True), unique=True),
        'path': Text(description='url path', nonempty=True),
        'shared_path': Text(description='path segment shared with mount'),
    })

    def __init__(self):
        try:
            self.application
        except AttributeError:
            self.application = self.dispatch

        middleware = self.configuration.get('middleware')
        if middleware:
            for attr in reversed(middleware):
                self.application = getattr(self, attr).wrap(self.application)

        self.path = '/' + self.configuration['path'].strip('/')
        self.shared_path = self.configuration.get('shared_path') or ''

        self.unshared_path = self.path
        if self.shared_path:
            self.shared_path = '/' + self.shared_path.strip('/')
            length = len(self.shared_path)
            if self.path[-length:] == self.shared_path:
                self.unshared_path = self.path[:-length]
            else:
                self.shared_path = ''

    def __call__(self, environ, start_response):
        try:
            return self.application(environ, start_response)
        except Exception:
            import traceback;traceback.print_exc()
            return InternalServerError()(environ, start_response)
        finally:
            ContextLocals.purge()

    def dispatch(self, environ, start_response):
        try:
            response = Response()
            self._dispatch_request(Request(environ), response)
            return response(environ, start_response)
        except HTTPException, error:
            return error(environ, start_response)
        except Exception:
            log('exception', 'exception raised during mount dispatch')
            return InternalServerError()(environ, start_response)

    def _dispatch_request(self, request, response):
        raise NotImplementedError()

class MiddlewareWrapper(object):
    def __init__(self, wrapper, application):
        self.application = application
        self.wrapper = wrapper

    def __call__(self, environ, start_response):
        return self.wrapper.dispatch(self.application, environ, start_response)

class Middleware(object):
    def wrap(self, application):
        return MiddlewareWrapper(self, application)

class MountDispatcher(object):
    def __init__(self, mounts=None):
        self.mounts = {}
        if mounts:
            for mount in mounts:
                self.mount(mount)

    def dispatch(self, environ, start_response):
        script = environ.get('PATH_INFO', '')
        pathinfo = ''

        mounts = self.mounts
        while '/' in script:
            try:
                mount = mounts[script]
            except KeyError:
                segments = script.split('/')
                script = '/'.join(segments[:-1])
                pathinfo = '/%s%s' % (segments[-1], pathinfo)
            else:
                break
        else:
            try:
                mount = mounts['/']
            except KeyError:
                return NotFound()(environ, start_response)

        environ['SCRIPT_NAME'] = environ.get('SCRIPT_NAME', '') + mount.unshared_path
        environ['PATH_INFO'] = mount.shared_path + pathinfo
        return mount(environ, start_response)

    __call__ = dispatch

    def mount(self, mount):
        path = mount.path
        if path not in self.mounts:
            self.mounts[path] = mount
        else:
            log('warning', 'mount %r declares duplicate path %r', mount, path)

def redirect_response(response, url, status=302):
    response.status_code = status
    response.headers.add('Location', url)
    return response
