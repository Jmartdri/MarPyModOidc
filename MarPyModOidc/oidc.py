#!/usr/bin/env python
# -*- coding: utf-8 -*-

from mod_python import apache
import base64
import json
import urllib
import httplib
from urlparse import urlparse
from contextlib import closing
import time

class Oidc:

    def __init__(self, req, session, base_log):
        self.req = req
        self.session = session
        self.base_log = base_log
        self.oidc_server_url = self.req.get_options()['OidcAuthServerUrl']
        self.oidc_client_id = self.req.get_options()['OidcClientId']
        self.oidc_client_secret = self.req.get_options()['OidcClientSecret']

    def handle_unauthorized(self):
        # Return HTTP_UNAUTHORIZED with appropriate header
        self.req.err_headers_out.add('WWW-Authenticate',
                                     'Basic realm="%s"' % self.req.auth_name())
        self.req.err_headers_out.add('Connection', 'close')
        return apache.HTTP_UNAUTHORIZED

    #return response from provider if ok, else return apache http status
    def request_oidc_provider(self, oidc_url, param):
        self.req.log_error(
                '%s - [OIDC] - Calling oidc provider to authentify basic authorization (%s) '
                % (self.base_log, oidc_url), apache.APLOG_INFO)
        try:
            parsed_url = urlparse(oidc_url)
            conn = httplib.HTTPConnection(parsed_url.netloc)
            headers = { "Content-type": "application/x-www-form-urlencoded", "Accept": "Application/json"}
            encoded_data = urllib.urlencode(param)

            try:                
                conn.request("POST", oidc_url[len(parsed_url.scheme)+len(parsed_url.netloc)+3:], body=encoded_data, headers=headers)
                response = conn.getresponse()

                if response.status != httplib.OK :
                    if response.status >= httplib.INTERNAL_SERVER_ERROR :
                        return response.status
                    else :
                        return self.handle_unauthorized()
                        
                data = response.read()
                self.req.log_error("%s - [OIDC] - Calling oidc provider return status OK "%self.base_log, apache.APLOG_INFO)
                return json.loads(data)
            except httplib.HTTPException as e:
                self.req.log_error(
                    '%s - [OIDC] - HTTPException :  %s  (data : %s)' %
                    (self.base_log, str(e), param), apache.APLOG_ERR)
                if hasattr(e, 'response') and e.response:
                    if e.response.status  >= httplib.INTERNAL_SERVER_ERROR :
                        return e.response.status
                    else:
                        return self.handle_unauthorized()
                else:
                    return e.response.status
            except Exception as e:
                self.req.log_error(
                    '%s - Exception :  %s' %
                    (self.base_log, str(e)), apache.APLOG_ERR)
                return apache.HTTP_INTERNAL_SERVER_ERROR

            finally:
                self.req.log_error("%s - [OIDC] - Closing http client after calling oidc"%self.base_log, apache.APLOG_INFO)
                conn.close
        except Exception as e:
            self.req.log_error(
                    '%s - [OIDC] - Exception :  %s ' %
                    (self.base_log, str(e)), apache.APLOG_ERR)
            return apache.HTTP_INTERNAL_SERVER_ERROR
                    

    def safe_str(self,obj):
        try:
            return str(obj)
        except UnicodeEncodeError as e:
            self.req.log_error(
                    '%s - UnicodeEncodeError :  %s ' %
                    (self.base_log, str(e)), apache.APLOG_ERR)
            return ""

    def decode_basic_authorization(self, raw):
        try:
            b64 = base64.b64decode(raw).decode("utf-8")
            usrPass = b64.split(':')
            return (self.safe_str(usrPass[0]), self.safe_str(usrPass[1]))
        except Exception as e:
            self.req.log_error(
                    "%s - Error on decoding http authorization :  %s" %
                    (self.base_log, str(e)),
                    apache.APLOG_ERR,
                )
            return None

    def get_authorization_header(self, auth):
        """Return tuple of type and value of authorization"""
        ah = auth.split(" ")
        if len(ah) != 2:
            self.req.log_error(
                "%s Unknown http authorization header = %s" %
                (self.base_log, str(auth)),
                apache.APLOG_ERR,
            )
            return None
        else:
            ah_type = ah[0]
            ah_value = ah[1]
            if (not ah_type or not ah_value
                    or str(ah_type).upper() not in ["BASIC", "BEARER"]):
                self.req.log_error(
                    "%s - Unknown http authorization header = %s" %
                    (self.base_log, str(auth)),
                    apache.APLOG_ERR,
                )
                return None
            return (str(ah_type).upper(), str(ah_value))

    def handle_basic(self, usernamePassword):

        self.clean_session()

        self.req.log_error(
            '%s - Handling Basic Access Authentication' % (self.base_log),
            apache.APLOG_INFO)

        if not usernamePassword or len(usernamePassword) != 2:
            self.req.log_error(
                '%s - Bad basic authentification provided = %s' %
                (self.base_log, usernamePassword[0]), apache.APLOG_INFO)
            return apache.BAD_REQUEST

        (username, password) = usernamePassword

        data = {
            'client_id': self.oidc_client_id,
            'client_secret': self.oidc_client_secret,
            'username': username,
            'password': password,
            'grant_type': 'password'
        }

        token_response = self.authentificateToOidcAndGetToken(data)
        if isinstance(token_response, int):  #response is apache status or dict
            self.clean_session()
            return token_response

        # insepect_response = getOidcIntrospection(data)
        # if isinstance(insepect_response, int):  #response is apache status or dict
        #     return insepect_response

        self.saveOidcAuthorizationOnSession(username, token_response)

        self.setAuthorizationHeaderToken(token_response["access_token"])

        self.req.log_error(
            '%s - User `%s` has been authenticated (Basic) to access to the URI'
            % (self.base_log, username), apache.APLOG_INFO)

        self.req.user = username
        return apache.OK

    def handle_existing_session(self, usernamePassword):
        second_now = time.time()
        token_expired_at = self.session["access_token_expire_in"]
        refresh_token_expired_at = self.session["refresh_token_expire_in"]

        if second_now < token_expired_at:
            self.req.log_error(
                "%s - Token session not yet expired ... continue " %
                self.base_log, apache.APLOG_INFO)
            self.req.user = self.session.get("user")
            self.setAuthorizationHeaderToken(self.session.get("access_token"))
            return apache.OK
        elif second_now < refresh_token_expired_at:
            self.req.log_error(
                "%s - Token session expired but Referesh token not yet expired... Go to refresh token "
                % self.base_log, apache.APLOG_INFO)
            return self.handle_refresh_token(usernamePassword)
        else:
            self.req.log_error(
                "%s - Token session and Referesh token are expired... Re-authentificated on oidc server with cache basic auth "
                % self.base_log, apache.APLOG_INFO)
            return self.handle_basic(usernamePassword)

    def handle_refresh_token(self, usernamePassword):
        data = {
            'client_id': self.oidc_client_id,
            'client_secret': self.oidc_client_secret,
            'grant_type': 'refresh_token',
            "refresh_token": self.session.get("refresh_token")
        }
        response = self.authentificateToOidcAndGetRefreshToken(data)
        if isinstance(response, int):  #response is apache status or dict
            self.clean_session()
            return response

        self.clean_session()
        self.req.user = usernamePassword[0]
        self.saveOidcAuthorizationOnSession(usernamePassword[0], response)

        self.setAuthorizationHeaderToken(response["access_token"])

        return apache.OK

    def setAuthorizationHeaderToken(self, token):
        self.req.headers_in["Authorization"] = "Bearer %s"%str(token)

    def saveOidcAuthorizationOnSession(self, username, token_response):
        self.clean_session()
        # self.req.log_error(
        #     '%s - Check data in session : Length %s ' %
        #     (self.base_log, len(self.session)), apache.APLOG_INFO)
        self.session.lock()
        self.session["user"] = username
        self.session["access_token"] = token_response["access_token"]
        self.session["refresh_token"] = token_response["refresh_token"]
        self.session["access_token_expire_in"] = int(
            token_response["expires_in"]) + time.time()
        self.session["refresh_token_expire_in"] = int(
            token_response["refresh_expires_in"]) + time.time()

        # self.req.log_error(
        #     '---------------------------------------------------------------------',
        #     apache.APLOG_INFO)

        # self.req.log_error('%s' % self.session["access_token"],
        #                    apache.APLOG_INFO)

        # self.req.log_error(
        #     '---------------------------------------------------------------------',
        #     apache.APLOG_INFO)

        # self.req.log_error('%s' % self.session["refresh_token"],
        #                    apache.APLOG_INFO)

        # self.req.log_error(
        #     '---------------------------------------------------------------------',
        #     apache.APLOG_INFO)

        self.session.save()
        self.session.unlock()
        self.req.log_error(
            '%s - Authorization from oidc saved to session' % self.base_log,
            apache.APLOG_INFO)

    def authentificateToOidcAndGetToken(self, data):
        return self.request_oidc_provider(
            '%s/protocol/openid-connect/token' % self.oidc_server_url, data)

    def getOidcIntrospection(self, data):
        return self.request_oidc_provider(
            '%s/protocol/openid-connect/token/introspect' %
            self.oidc_server_url, data)

    def authentificateToOidcAndGetRefreshToken(self, data):
        return self.request_oidc_provider(
            '%s/protocol/openid-connect/token' % self.oidc_server_url, data)

    def clean_session(self):
        self.session.lock()
        self.session.clear()
        self.session.save()
        self.session.unlock()
        self.req.log_error(
            "%s - Session authorization data cleaned " % self.base_log,
            apache.APLOG_INFO)
