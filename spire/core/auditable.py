import uuid
from datetime import date, datetime
import hashlib 

from spire.core import Unit, Dependency, adhoc_configure
from spire.support.logs import LogHelper
from mesh.constants import OK, DELETE, POST, PUT, GONE
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

    def _prepare_audit_data_n(self, method, status, subject, audit_data, add_params):
        '''
        new method called within send_audit_data_n for correcting entries for AuditRecord data
        @param method: string containing http method, e.g. POST
        @type method: string
        @param status: OK or error code, Http return code (200, 500 etc.)
        @type status: string
        @param subject: object for which an auditing event should be written 
        @type subject: subclass of Controller
        @param audit_data: object with members like event_details and event_payload 
        @type audit_data: AuditRecord
        @param add_params:  additional parameters for processing, set by the calling method, e.g. add_params['optype']=OPTYPE_USER_CREATE 
        @type add_params: dictionary
        '''
        raise NotImplementedError

    def send_audit_data_n(self, request, response, subject, data, add_params):
        '''
        :param request: object containing http request data 
        :type request: Http request 
        :param response: response object which contains status information 
        :type response: Http response   
        :param subject: object for which a change should be audited 
        :type subject:  subtype of Model
        :param data:   contains the request payload
        :type data: dictionary
        :param add_params: additional parameters for processing, set by the calling method, e.g. add_params['optype']=OPTYPE_USER_CREATE  
        :type add_params:
        '''

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
        add_params = add_params or {}
        
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
                if data:
                    data.update(subject.extract_dict())
                else :
                    # data is None if this method is called by "delete user" method
                    data = subject.extract_dict()

        if method == POST and request.subject:
            # a POST request passing the subject's id, should normally rather be a PUT request
            # so translate that, accordingly
            method = PUT
        
        if method == 'TASK':
            # if the request was submitted by an automated task, 
            # we expect to find the actual op in data
            method = add_params.pop('task_op', POST)
            taskname = add_params.get('task','')
            actor_detail = {
                ACTOR_DETAIL_USERNAME: ACTOR_SYSTEM,
                ACTOR_DETAIL_FIRSTNAME: 'automated-task',
                ACTOR_DETAIL_LASTNAME: taskname,
                ACTOR_DETAIL_EMAIL: ''
            }
            audit_data[AUDIT_ATTR_ACTOR] = actor_detail
        
        
        if data:        
            self.validate_payload(data)
            event_payload.update(data)
            
        if subject is None:
            if status == OK and response.content and 'id' in response.content:
                add_params['id'] = response.content.get('id')
            else: 
                if request.subject :
                    ## if this method is called for delete then there is no subject and the object id is 
                    ## available only via request.subject where request.subject is a string like
                    ## str: b8dc6fa8-cd70-4927-bcb1-5a4571ececd7
                    ##  
                    try:
                        uuid.UUID(request.subject)
                        add_params['id'] =  request.subject   
                    except Exception as e :
                        log('exception', e)
                        pass     
        else:
            try:
                add_params['id'] = subject.id
            except AttributeError:
                pass
        
        if actor_id != '':     
            audit_data[AUDIT_ATTR_ACTOR_ID] = actor_id

        ## in case of an exception in credentialreset there is no value for logon
        ## user and we must check the request header for information on origin
        ## BUT the polymorphic prepare routines gets no request object
        if actor_id == ''   :
            add_params['x-forwarded-for']= request.context.get('x-forwarded-for','unknown')
            
        if status == OK:
            audit_data[AUDIT_ATTR_RESULT] = REQ_RESULT_SUCCESS
        else:
            audit_data[AUDIT_ATTR_RESULT] = REQ_RESULT_FAILED

        self._prepare_audit_data_n(method, status, subject, audit_data, add_params)
        
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
            log('debug','===> audit_data = %s' % str(audit_data))
            self.AuditEvent.create(**audit_data)
        except RequestError as exc:
            raise AuditCreateError(exc.content)

    def validate_payload(self, payload):
        
        """ none of the attributes included in the payload may be of type datetime
            so convert these items to an ISO8601 string representation
            further, string values may not include any double-quotes, so escape those.
            do the same thing for nested dicts
        """
        if not payload:
            return
        
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