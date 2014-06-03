import base64
import json
import urllib
import urlparse
import uuid
import requests
import xml.etree.ElementTree as ET

__author__ = 'haho0032'
import logging
import string
from urlparse import parse_qs
from auth.base import Authenticate
from dirg_util.http_util import Response, HttpHandler, Unauthorized, Redirect

__author__ = 'haho0032'

#Add a logger for this class.
logger = logging.getLogger("dirg_util.auth")


class CasAuthentication(Authenticate):
    #Standard login url for a CAS server.
    CONST_CASLOGIN = "/cas/login?"
    #Standard URL for validation of a ticket for a CAS server.
    CONST_CAS_VERIFY_TICKET = "/serviceValidate"
    #Standard name for the parameter containing a CAS ticket.
    CONST_TICKET = "ticket"
    #Standard name for the parameter containing the service url (callback url).
    CONST_SERVICE = "service"
    #A successful verification of a ticket against a CAS service will contain
    # this XML element.
    CONST_AUTHSUCCESS = "authenticationSuccess"
    #If a success full verification of a CAS ticket has been perform, the uid
    # will be containd in a XML element
    #with this name.
    CONST_USER = "user"
    #Used for preventing replay attacks.
    CONST_NONCE = "nonce"
    #Parameter name for queries to be sent back on the URL, after successful
    # authentication.
    CONST_QUERY = "query"
    #The name for the CAS cookie, containing query parameters and nonce.
    CONST_CAS_COOKIE = "cascookie"
    #The parameter name in the cookie containing the filter.
    CONST_FILTER = "filter"

    def __init__(self, cas_server, service_url, extra_validation=None,
                 cookie_dict=None, cookie_object=None):
        """

        """
        Authenticate.__init__(self, cookie_dict, cookie_object)
        self.cas_server = cas_server
        self.service_url = service_url
        self.extra_validation = extra_validation

    def filter_query(self, query_dict, filter):
        filter_query = ""
        if filter is not None:
            filter_dict = {}
            for item in filter:
                filter_dict[item] = self.dict_value(query_dict,item)
            if len(filter_dict.keys()) > 0:
                filter_query = "&" + urllib.urlencode(filter_dict)
        return filter_query

    def create_redirect(self, query, acr, filter={}):
        """
        Performs the redirect to the CAS server.

        :rtype : Response
        :param query: All query parameters to be added to the return_to URL
            after successful authentication.
        :return: A redirect response to the CAS server.
        """
        filter_query = ""
        try:
            req = urlparse.parse_qs(query)
            if self.CONST_ACR not in req:
                if len(req) > 0:
                    query += "&"
                else:
                    query += "?"
                query += self.CONST_ACR + "=" + acr
                req[self.CONST_ACR] = [acr]

            filter_query = self.filter_query(req, filter)
        except KeyError:
            pass

        nonce = uuid.uuid4().get_urn()
        service_url = urllib.urlencode(
            {self.CONST_SERVICE: self.get_service_url(nonce, filter_query)})
        cas_url = self.cas_server + self.CONST_CASLOGIN + service_url
        cookie = self.create_cookie(
            '{"' + self.CONST_NONCE + '": "' + base64.b64encode(nonce) + '", "' + self.CONST_QUERY + '": "' +
            base64.b64encode(query) + '", "' + self.CONST_FILTER + '": "' + self.encrypt_list(filter) +'"}',
            self.CONST_CAS_COOKIE,
            self.CONST_CAS_COOKIE, path="/")
        return Redirect(cas_url, headers=[cookie])

    def create_response(self, query=None, **kwargs):
        """
        Put up the login form
        """
        return self.create_redirect(query)

    def handle_callback(self, ticket, service_url):
        """
        Handles the callback from the CAS server.

        :rtype : String
        :param ticket: Onetime CAS ticket to be validated.
        :param service_url: The URL the CAS server redirected to.
        :return: Uid if the login was successful otherwise None.
        """
        data = {self.CONST_TICKET: ticket, self.CONST_SERVICE: service_url}
        resp = requests.get(self.cas_server + self.CONST_CAS_VERIFY_TICKET,
                            params=data)
        root = ET.fromstring(resp.content)
        for l1 in root:
            if self.CONST_AUTHSUCCESS in l1.tag:
                for l2 in l1:
                    if self.CONST_USER in l2.tag:
                        if self.extra_validation is not None:
                            if self.extra_validation(l2.text):
                                return l2.text
                            else:
                                return None
                        return l2.text
        return None

    def get_service_url(self, nonce, filter_query):
        """
        Creates the service url for the CAS server.

        :rtype : String
        :param nonce: The nonce to be added to the service url.
        :return: A service url with a nonce.
        """
        #if acr is None:
        #    acr = ""
        return self.service_url + "?" + self.CONST_NONCE + "=" + nonce + filter_query
            #"&acr_values=" + acr

    def verify(self, request, cookie, **kwargs):
        """
         Verifies if the authentication was successful.

         :rtype : Response
         :param request: Contains the request parameters.
         :param cookie: Cookies sent with the request.
         :param kwargs: Any other parameters.
         :return: If the authentication was successful: a redirect to the
         return_to url.
                  Otherwise a unauthorized response.
         :raise: ValueError
         """
        logger.debug("verify(%s)" % request)
        if isinstance(request, basestring):
            _dict = parse_qs(request)
        elif isinstance(request, dict):
            _dict = request
        else:
            raise ValueError("Wrong type of input")
        try:
            cas_cookie, _ts, _typ = self.getCookieValue(cookie,
                                                        self.CONST_CAS_COOKIE)
            data = json.loads(cas_cookie)
            nonce = base64.b64decode(data[self.CONST_NONCE])
            filter = self.decrypt_list(data[self.CONST_FILTER])
            if nonce != self.dict_value(_dict,self.CONST_NONCE):
                logger.warning(
                    'Someone tried to login without a correct nonce!')
                return False, None, None
            #acr = None
            filter_query = ""
            try:
                #acr = _dict["acr_values"][0]
                filter_query = self.filter_query(_dict, filter)
            except KeyError:
                pass
            uid = self.handle_callback(_dict[self.CONST_TICKET],
                                       self.get_service_url(nonce, filter_query)) # acr))
            if uid is None or len(str(uid)) == 0:
                logger.info('Someone tried to login, but was denied by CAS!')
                return False, None, None

            return True, uid, base64.b64decode(data[self.CONST_QUERY])
        except:
            logger.fatal('Metod verify in user_cas.py had a fatal exception.',
                         exc_info=True)
            return False, None, None