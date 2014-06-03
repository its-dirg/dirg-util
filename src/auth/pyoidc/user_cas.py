
import logging
from auth.cas import CasAuthentication
from oic.utils.http_util import Redirect
from oic.utils.http_util import Unauthorized
from auth.pyoidc.user import _UserAuthnMethod

logger = logging.getLogger(__name__)


#This class handles user authentication with CAS.
class CasAuthnMethod(_UserAuthnMethod):
    #Parameter name for queries to be sent back on the URL, after successful
    # authentication.
    CONST_QUERY = "query"

    def __init__(self, srv, cas_server, service_url, return_to, acr,
                 extra_validation=None):
        """
        Constructor for the class.
        :param srv: Usually none, but otherwise the oic server.
        :param cas_server: Base URL to the cas server.
        :param service_url: BASE url to the service that will use CAS. In
        this case the oic server's verify URL.
        :param return_to: The URL to return to after a successful
        authentication.
        """
        _UserAuthnMethod.__init__(self, srv, authn_helper=CasAuthentication(cas_server, service_url,
                                                                            extra_validation=None,
                                                                            cookie_dict=None,
                                                                            cookie_object=None))
        self.acr = acr
        self.return_to = return_to

    def __call__(self, query, *args, **kwargs):

        filter = [
            "acr_values"
        ]

        return self.authn_helper.create_redirect(query, self.acr, filter)

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
        try:
            valid, uid, return_to_query = self.authn_helper.verify(request, cookie, **kwargs)
            if valid:
                cookie = self.authn_helper.create_authentication_cookie(uid, "casm")
                return_to = self.generateReturnUrl(self.return_to, uid)
                if '?' in return_to:
                    return_to += "&"
                else:
                    return_to += "?"
                return_to += return_to_query
                return Redirect(return_to, headers=[cookie])
            else:
                logger.fatal('User is not valid.', exc_info=True)
                return Unauthorized("You are not authorized!")
        except:
            logger.fatal('Metod verify in user_cas.py had a fatal exception.', exc_info=True)
            return Unauthorized("You are not authorized!")
