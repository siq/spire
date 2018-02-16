from spire.wsgi.util import Middleware

class ContextMiddleware(Middleware):
    def __init__(self, parsers, key='request.context'):
        self.key = key
        self.parsers = parsers

    def dispatch(self, application, environ, start_response):
        self._parse_context(environ)
        return application(environ, start_response)

    def _parse_context(self, environ):
        context = environ.get(self.key)
        if context is None:
            context = environ[self.key] = {}

        for parser in self.parsers:
            parser(environ, context)

class HeaderParser(object):
    def __init__(self, prefix='HTTP_X_SPIRE_'):
        self.prefix = prefix
        self.prefix_length = len(prefix)

    def __call__(self, environ, context):
        prefix = self.prefix
        length = self.prefix_length

        for name, value in environ.iteritems():
            if name[:length] == prefix:
                context[name[length:].lower().replace('_', '-')] = value

class SessionParser(object):
    def __init__(self, key='request.context', environ_key='request.session'):
        self.environ_key = environ_key
        self.key = key

    def __call__(self, environ, context):
        session = environ.get(self.environ_key)
        if session:
            value = session.get(self.key)
            if value:
                context['session-id'] = session.sid
                context.update(value)
