import os

from scheme import Json, Text
from werkzeug.exceptions import MethodNotAllowed
from werkzeug.formparser import parse_form_data

from spire.core import Configuration, Unit
from spire.util import uniqid
from spire.wsgi.util import Mount

class UploadEndpoint(Mount):
    configuration = Configuration({
        'upload_directory': Text(nonempty=True, default='/tmp'),
    })

    def _dispatch_request(self, request, response):
        directory = self.configuration['upload_directory']
        if request.method == 'GET':
            return
        elif request.method != 'POST':
            raise MethodNotAllowed()

        mapping = {}
        for name, uploaded_file in request.files.iteritems():
            filename = mapping[name] = '%s_%s' % (uniqid(), uploaded_file.filename)
            uploaded_file.save(os.path.join(directory, filename))

        response.mimetype = 'application/json'
        response.data = Json.serialize(mapping)

class UploadManager(Unit):
    configuration = Configuration({
        'upload_directory': Text(nonempty=True, default='/tmp'),
    })

    def acquire(self, id):
        return open(self.find(id))

    def dispose(self, id):
        try:
            filename = self.find(id)
        except ValueError:
            pass
        else:
            os.unlink(filename)

    def find(self, id):
        filename = os.path.join(self.configuration['upload_directory'], id)
        if os.path.exists(filename):
            return filename
        else:
            raise ValueError(id)
