import logging
import urlparse
import time
from oic.utils.authn.user import UserAuthnMethod, create_return_url
from auth.form import DirgUsernamePasswordYubikeyMako
from oic.utils.http_util import Redirect
from oic.utils.http_util import Unauthorized

__author__ = 'haho0032'

logger = logging.getLogger(__name__)


class _UserAuthnMethod(UserAuthnMethod):
    def __init__(self, srv, ttl=5, authn_helper=None):
        UserAuthnMethod.__init__(self, srv, ttl)
        self.query_param = "upm_answer"
        self.authn_helper = authn_helper
        self.userauthnmethod = UserAuthnMethod(srv, ttl)

    def __call__(self, *args, **kwargs):
        raise NotImplemented

    def set_srv(self, srv):
        self.srv = srv
        if self.authn_helper is not None:
            self.authn_helper.srv = srv

    def authenticated_as(self, cookie=None, **kwargs):
        if self.authn_helper is not None:
            return self.authn_helper.authenticated_as(cookie, **kwargs)
        self.userauthnmethod.authenticated_as(cookie=None, **kwargs)

    def generateReturnUrl(self, return_to, uid):
        return create_return_url(return_to, uid, **{self.query_param: "true"})


class UsernamePasswordMako(_UserAuthnMethod):
    """Do user authentication using the normal username password form in a
    WSGI environment using Mako as template system"""

    def __init__(self, username_query_key, srv, mako_template, template_lookup, pwd, return_to="",
                 templ_arg_func=None, cookie_dict=None, password_query_key=None, yubikey_db=None, yubikey_server=None,
                 yubikey_otp_key=None):
        """
        :param srv: The server instance
        :param mako_template: Which Mako template to use
        :param pwd: Username/password dictionary like database
        :param return_to: Where to send the user after authentication
        :return:
        """

        authn_helper=DirgUsernamePasswordYubikeyMako(username_query_key, mako_template, template_lookup, pwd,
                                                     password_query_key, yubikey_db, yubikey_server, yubikey_otp_key,
                                                     cookie_dict=cookie_dict, )

        _UserAuthnMethod.__init__(self, srv, authn_helper=authn_helper)


        self.return_to = return_to
        if templ_arg_func:
            self.templ_arg_func = templ_arg_func
        else:
            self.templ_arg_func = self.template_args

    @staticmethod
    def template_args(**kwargs):
        """
        Method to override if necessary, dependent on the page layout
        and context

        :param kwargs:
        :return:
        """
        acr = None
        try:
            req = urlparse.parse_qs(kwargs["query"])
            acr = req["acr_values"][0]
        except:
            pass

        argv = {"password": "",
                "otp": "",
                "action": "verify",
                "acr": acr}

        try:
            argv["login"] = kwargs["as_user"]
        except KeyError:
            argv["login"] = ""

        for param in ["policy_uri", "logo_uri", "query"]:
            try:
                argv[param] = kwargs[param]
            except KeyError:
                argv[param] = ""

        return argv

    def __call__(self, cookie=None, **kwargs):
        """
        Put up the login form
        """
        return self.authn_helper.create_response(self.templ_arg_func(**kwargs), cookie)

    def verify(self, request, **kwargs):
        """
        Verifies that the given username and password was correct
        :param request: Either the query part of a URL a urlencoded
            body of a HTTP message or a parse such.
        :param kwargs: Catch whatever else is sent.
        :return: redirect back to where ever the base applications
            wants the user after authentication.
        """
        try:
            valid, uid, parameters = self.authn_helper.verify(request)
        except (AssertionError, KeyError):
            resp = Unauthorized("Unknown user or wrong password")
        else:
            if valid:
                cookie = self.authn_helper.create_authentication_cookie(uid, "upm")
                try:
                    _qp = parameters["query"][0]
                except KeyError:
                    _qp = ""
                return_to = self.generateReturnUrl(self.return_to, _qp)
                resp = Redirect(return_to, headers=[cookie])
            else:
                resp = Unauthorized("Unknown user or wrong password")

        return resp

    def done(self, areq):
        try:
            _ = areq[self.query_param]
            return False
        except KeyError:
            return True