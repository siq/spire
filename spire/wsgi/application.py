from scheme import Sequence, Text, Tuple
from scheme.supplemental import ObjectReference
from werkzeug.exceptions import HTTPException, InternalServerError, NotFound
from werkzeug.local import Local, release_local
from werkzeug.routing import Map, RequestRedirect, Rule
from werkzeug.wrappers import Request as WsgiRequest, Response

from spire.core import *
from spire.local import ContextLocals
from spire.util import call_with_supported_params, enumerate_modules, is_class, is_module, is_package
from spire.wsgi.templates import TemplateEnvironment
from spire.wsgi.util import Mount

ContextLocal = ContextLocals.declare('wsgi.request')

class Request(WsgiRequest):
    """A WSGI request."""

    def __init__(self, application, environ, urls):
        super(Request, self).__init__(environ)
        self.application = application
        self.endpoint = None
        self.params = None
        self.template_context = {}
        self.urls = urls

        for name, value in environ.iteritems():
            if name[:8] == 'request.':
                setattr(self, name[8:], value)

    @property
    def forwarded_ip(self):
        return self.headers.get('X-Forwarded-For')

    def bind(self):
        ContextLocal.push(self)

    @classmethod
    def current_request(cls):
        return ContextLocal.get()

    def match(self):
        if self.endpoint:
            return

        try:
            self.endpoint, self.params = self.urls.match()
        except (HTTPException, RequestRedirect), error:
            return error
        else:
            self.params['endpoint'] = self.endpoint

    def render(self, template, context=None, response=None, mimetype='text/html', **params):
        response = response or Response(mimetype=mimetype)
        response.data = self.render_template(template, context, **params)
        return response

    def render_template(self, template, context=None, **params):
        template_context = self.template_context
        for contribution in (context, params):
            if contribution:
                template_context.update(contribution)

        return self.application.environment.render_template(template, template_context)

    def unbind(self):
        ContextLocal.pop()

    def url_for(self, endpoint, **params):
        return self.urls.build(endpoint, params)

class Application(Mount):
    """A WSGI application."""

    configuration = Configuration({
        'mediators': Sequence(Text(nonempty=True), unique=True),
        'templates': Sequence(Tuple((Text(nonempty=True), Text(nonempty=True)))),
        'urls': ObjectReference(nonnull=True, required=True),
        'views': Sequence(ObjectReference(nonnull=True), unique=True),
    })

    def __init__(self, urls, views=None, templates=None, mediators=None):
        super(Application, self).__init__()
        if isinstance(urls, (list, tuple)):
            urls = Map(list(urls))
        if not isinstance(urls, Map):
            raise Exception()

        self.urls = urls
        self.views = self._collect_views(views)

        self.environment = None
        if templates:
            self.environment = TemplateEnvironment(templates)

        self.mediators = []
        if mediators:
            for mediator in mediators:
                attr = getattr(self, mediator)
                self.mediators.append(attr)

    def contribute_params(self):
        return {'application': self}

    def dispatch(self, environ, start_response):
        try:
            return self._dispatch_request(environ)(environ, start_response)
        except HTTPException, error:
            return error(environ, start_response)

    def _dispatch_request(self, environ):
        urls = self.urls.bind_to_environ(environ)
        request = Request(self, environ, urls)
        response = None

        request.bind()
        try:

            mediators = self.mediators
            for mediator in mediators:
                response = mediator.mediate_request(request)
                if isinstance(response, Response):
                    break
                else:
                    response = None

            view = None
            if not response:
                response = request.match()
                if not response:
                    view = self.views.get(request.endpoint)
                    if not view:
                        view = self.views.get('default')
                    if not view:
                        response = NotFound()

            if not response:
                try:
                    response = call_with_supported_params(view, request, **request.params)
                    if not isinstance(response, Response):
                        response = Response(response)
                except HTTPException:
                    raise
                except Exception, exception:
                    for mediator in reversed(mediators):
                        response = mediator.mediate_exception(request, exception)
                        if response:
                            break
                    else:
                        import traceback;traceback.print_exc()
                        response = InternalServerError()

            for mediator in reversed(mediators):
                response = mediator.mediate_response(request, response) or response

            return response

        finally:
            request.unbind()

    def _collect_views(self, targets):
        views = {}
        for target in (targets or []):
            if is_package(target):
                modules = enumerate_modules(target, True)
            elif is_module(target):
                modules = [target]
            else:
                raise Example()

            for module in modules:
                for attr, value in module.__dict__.iteritems():
                    try:
                        viewable = getattr(value, '__viewable__', None)
                    except Exception:
                        viewable = False
                    if viewable:
                        if is_class(value):
                            value = value()
                        views[value.endpoint] = value
        return views

class Mediator(object):
    """A request/response mediator."""

    def mediate_exception(self, request, exception):
        return None

    def mediate_request(self, request):
        """
        returns:
            None or a Response object to short-circuit the response creation
        """
        return None

    def mediate_response(self, request, response):
        return response

def view(endpoint):
    if hasattr(endpoint, '__call__'):
        endpoint.__viewable__ = True
        endpoint.endpoint = endpoint.__name__
        return endpoint
    else:
        def decorator(obj):
            obj.__viewable__ = True
            obj.endpoint = endpoint
            return obj
        return decorator
