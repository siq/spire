import os

from werkzeug.exceptions import MethodNotAllowed
from spire.wsgi.util import Mount

class CsvDownloadEndPoint(Mount):

    def _dispatch_request(self, request, response):
        if request.method == 'GET':
            return
        elif request.method != 'POST':
            raise MethodNotAllowed()

        mimetype = request.form.get('mimetype', 'text/csv')
        filename = request.form.get('filename', 'data.csv')
        data = request.form.get('data', '')
        response.headers = {
            'content-type': mimetype + '; charset=utf-8',
            'content-disposition': 'attachment;filename='+filename
        }
        response.data = data
