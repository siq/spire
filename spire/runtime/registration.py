from scheme import Json

from spire.wsgi.util import Mount

class ServiceEndpoint(Mount):
    def __init__(self, runtime, service):
        super(ServiceEndpoint, self).__init__()
        self.runtime = runtime
        self.service = service

    def _dispatch_request(self, request, response):
        service = self.service
        if request.method == 'GET':
            return self._prepare_response(response,
                {'id': service['id'], 'pid': self.runtime.pid})

        data = Json.unserialize(request.data)
        if data['status'] == 'restarting':
            self._prepare_response(response, {'status': 'restarting'})
            self.runtime.reload()
        elif data['status'] == 'starting':
            content = self.runtime._execute_service_startup(self.service['id'], data.get('stage'))
            self._prepare_response(response, content)

    def _prepare_response(self, response, content):
        response.mimetype = 'application/json'
        response.data = Json.serialize(content)
