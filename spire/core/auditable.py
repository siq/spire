import uuid
from datetime import date, datetime
import hashlib 

from spire.core import Unit, Dependency, adhoc_configure
from spire.support.logs import LogHelper
from mesh.constants import OK, DELETE, POST, PUT
from mesh.exceptions import AuditCreateError, RequestError
from audit.constants import *
from audit.auditconfiguration import AuditConfigParms, AuditConfiguration
from scheme.timezone import current_timestamp
from scheme.util import format_structure
from bastion.security.constants import CONTEXT_CREDENTIAL_USERNAME, CONTEXT_CREDENTIAL_TYPE

log = LogHelper(__name__)

# mesh dependency configuration
adhoc_configure({
    'mesh:audit': {
        'bundle': 'audit.API',
        'url': 'http://localhost:9986/api'
    }
})

# ToolDependency class
class ToolDependency(Unit):
    from spire.mesh.units import MeshDependency
    audit = MeshDependency('audit')


__all__ = ('Configurable', 'Registry')

class Auditable(object):
    """ A mixin class which indicates that subclasses are collecting audit information
        and provides basic implementations for the necessary methods
    """
    audit_config = Dependency(AuditConfiguration)

    from audit import API
        
    bundle = API
    config = ToolDependency()
    AuditEvent = config.audit.bind('audit/1.0/record')

        
    def needs_audit(self, request, subject):
        return False

    def _prepare_audit_data(self, method, status, resource_data, audit_data):
        raise NotImplementedError
    
    def send_audit_data(self, request, response, subject, data):

        # first check, whether auditing is configured for the given
        # controller at all!
        if not self.is_audit_enabled():
            log('info','auditing is DISABLED')
            return
        if not self.needs_audit(request, subject):
            log('info','auditing for this request is NOT enabled')
            return

        event_details = {}
        event_payload = {}
        resource_data = data or {}
        
        audit_data = {
            AUDIT_ATTR_EVENT_DATE: current_timestamp(),
            AUDIT_ATTR_DETAILS: event_details,
            AUDIT_ATTR_PAYLOAD: event_payload,
        }
        
        # create a default correlation id, which may or may not be overwritten
        # by each controller.
        audit_data[AUDIT_ATTR_CORRELATION_ID]= str(uuid.uuid4())
        
        # extract audit relevant details
        actor_id = request.context.get('user-id', '')
        method = request.headers['REQUEST_METHOD']
        status = response.status or OK
        
        audit_data[AUDIT_ATTR_ORIGIN] = self._get_origin(request.headers)
        
        if method == DELETE:
            if subject:
                resource_data.update(subject.extract_dict())

        
        if method == POST and not subject is None:
            # a POST request passing the subject's id, should normally rather be a PUT request
            # so translate that, accordingly
            method = PUT
        
        if method == 'TASK':
            # if the request was submitted by an automated task, 
            # we expect to find the actual op in data
            method = resource_data.pop('task_op', POST)
            taskname = resource_data.pop('task','')
            actor_detail = {
                ACTOR_DETAIL_USERNAME: ACTOR_SYSTEM,
                ACTOR_DETAIL_FIRSTNAME: 'automated-task',
                ACTOR_DETAIL_LASTNAME: taskname,
                ACTOR_DETAIL_EMAIL: ''
            }
            audit_data[AUDIT_ATTR_ACTOR] = actor_detail
        
                
        self.validate_payload(resource_data)
        event_payload.update(resource_data)
            
        if subject is None:
            if status == OK and response.content and 'id' in response.content:
                resource_data['id'] = response.content.get('id')
        else:
            try:
                resource_data['id'] = subject.id
            except AttributeError:
                pass
        
        if actor_id != '':     
            audit_data[AUDIT_ATTR_ACTOR_ID] = actor_id
            
        if status == OK:
            audit_data[AUDIT_ATTR_RESULT] = REQ_RESULT_SUCCESS
        else:
            audit_data[AUDIT_ATTR_RESULT] = REQ_RESULT_FAILED

        #_debug('+send_audit_data - request actor', str(actor_id))        
        #_debug('+send_audit_data - request method', method)        
        #_debug('+send_audit_data - response status', status)
        #_debug('+send_audit_data - subject id', resource_data.get('id', None))        

        self._prepare_audit_data(method, status, resource_data, audit_data)
        #_debug('+send_audit_data - audit record', str(audit_data))        
        
        self._create_audit_event(audit_data)

    
    def send_authorization_audit(self, user_id, environ, success ):

        if not self.is_audit_enabled():
            log('info','auditing is DISABLED')
            return
        if not self.is_audit_enabled_for(AuditConfigParms.AUDIT_AUTH):
            log('info', 'auditing for login/logout is NOT enabled.')
            return
        
        event_details = {}
        event_payload = {}
        actor_detail = {}
        
        audit_data = {
            AUDIT_ATTR_EVENT_DATE: current_timestamp(),
            AUDIT_ATTR_DETAILS: event_details,
            AUDIT_ATTR_PAYLOAD: event_payload,
            AUDIT_ATTR_EVENT_CATEGORY: CATEGORY_AUTHENTICATION
        }

        audit_data[AUDIT_ATTR_ORIGIN] = self._get_origin(environ)
                
        context = environ['request.context']
        close_session = context.get('close-session','false')
        if close_session == 'true':
            audit_data[AUDIT_ATTR_OPTYPE] = OPTYPE_LOGOUT
        else:
            audit_data[AUDIT_ATTR_OPTYPE] = OPTYPE_LOGIN
            
        correlation_id = str(uuid.uuid4())
        audit_data[AUDIT_ATTR_CORRELATION_ID]= correlation_id

        if success:
            audit_data[AUDIT_ATTR_RESULT] = REQ_RESULT_SUCCESS
        else:
            audit_data[AUDIT_ATTR_RESULT] = REQ_RESULT_FAILED

        if user_id is not None:
            audit_data[AUDIT_ATTR_ACTOR_ID] = user_id
        else:
            username = context.get(CONTEXT_CREDENTIAL_USERNAME, '')
            actor_detail = {
                ACTOR_DETAIL_USERNAME: username,
                ACTOR_DETAIL_FIRSTNAME: '',
                ACTOR_DETAIL_LASTNAME: '',
                ACTOR_DETAIL_EMAIL: ''
            }
            audit_data[AUDIT_ATTR_ACTOR] = actor_detail
            
        event_details['type'] = 'authentication'
        event_details['source_ip'] = context.get('x-forwarded-for','')
        event_details['target_host'] = environ.get('HTTP_HOST','')
        
        credtype = context.get(CONTEXT_CREDENTIAL_TYPE)
        if credtype is not None:
            if credtype == 'password':
                event_details['method'] = AUTHENTICATION_METHOD_LOCAL
            else:
                event_details['method'] = AUTHENTICATION_METHOD_LDAP 
        
        #_debug('+send_audit_data - audit record', str(audit_data))        
        
        # insert rest call to SIQ Audit here!
        # assume that failure to create/write the audit event will throw an exception
        # which we'll deliberately NOT catch, here!
        self._create_audit_event(audit_data)
        
        return correlation_id
        
           
    def _create_audit_event(self, audit_data):
        # since the following code is NOT calling directly into controller, we must catch
        # exceptions created therein and ensure they are translated back to an AuditError
        try:
            self.AuditEvent.create(**audit_data)
        except RequestError as exc:
            raise AuditCreateError(exc.content)

    def validate_payload(self, payload):
        
        """ none of the attributes included in the payload may be of type datetime
            so convert these items to an ISO8601 string representation
            further, string values may not include any double-quotes, so escape those.
            do the same thing for nested dicts
        """
        for key, val in payload.iteritems():
            if isinstance(val, dict):
                self.validate_payload(val)
            if isinstance(val, (datetime, date)):
                pattern = '%Y-%m-%dT%H:%M:%SZ'
                payload[key] = val.strftime(pattern) 
            if isinstance(val, str):
                val.replace('"','\\"')
    
    def create_correlation_key(self, *digest_attribs):
        
        hashkey = hashlib.md5()
        
        for attr in digest_attribs:
            hashkey.update(attr)
        
        digest = hashkey.hexdigest()
        return str(uuid.UUID(hex=digest))

    def _get_origin(self, request_headers):
        
        origin = request_headers.get('SERVER_NAME')
        if not origin or origin == 'localhost':
            origin = request_headers.get('uwsgi.node')
            
        return origin
    
    def is_audit_enabled(self):
        return self.audit_config.configuration[AuditConfigParms.AUDIT_ENABLED]
    
    def is_audit_enabled_for(self, component):
        return (self.audit_config.configuration[AuditConfigParms.AUDIT_ENABLED] and self.audit_config.configuration[component])
    

"""    
def _debug(msg, obj=None, includeStackTrace=False):
    import datetime
    import inspect
    import traceback
    frame = inspect.currentframe()
    fileName  =  frame.f_code.co_filename
    line = ' [%s] %s' % (fileName, msg)
    if obj != None:
        line += ': ' + str(obj)
    print 'DEBUG:' + line
    if includeStackTrace:
        print 'STACK' + ':' * 75
        for s in traceback.format_stack():
            print(s.strip())
        print ':' * 80
    with open('/tmp/_debug_','a') as fout:
        fout.write(str(datetime.datetime.now().time()) + line + '\n')
        if includeStackTrace:
            fout.write('STACK:\n')
            for s in traceback.format_stack():
                fout.write('  ' + s.strip() + '\n')
        fout.flush()
"""        