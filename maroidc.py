#!/usr/bin/env python
# -*- coding: utf-8 -*-

# /!\ this code is inspired from https://github.com/Legrandin/PyAuthenNTLM2

from mod_python import apache, Session
from MarPyModOidc.oidc import Oidc

def isUserSessionEqualUserAuth(userAuth, userSession):
    return userAuth and userSession and userAuth == userSession


def authenhandler(req):
    # The request handler called by mod_python in the authentication phase

    session = Session.Session(req, lock=0)

    base_log = "[ModPyOidc] session : { id :  %s , new? : %s, len : %s}, con : %s, %s %s" % (
        session.id()[:6], session.is_new(),  len(session), req.connection.id, req.method, req.unparsed_uri[-20:])

    try:
        oidc = Oidc(req, session, base_log)
    except KeyError as e:
        req.log_error('%s - Incorrect configuration = %s' % (base_log, str(e)),
                      apache.APLOG_CRIT)
        oidc.clean_session()
        return apache.HTTP_INTERNAL_SERVER_ERROR

    req.log_error("%s - Start handling request " % base_log, apache.APLOG_INFO)

    # Extract authorization header
    auth_header = req.headers_in.get("Authorization")

    # If no  Authorization header value provided => HTTP_UNAUTHORIZED
    if not auth_header:
        req.log_error("%s - Not Http Authorization provided " % base_log,
                      apache.APLOG_INFO)
        oidc.clean_session()
        return oidc.handle_unauthorized()

    # Else parse Authorization header value
    auth = oidc.get_authorization_header(auth_header)
    if not auth:
        oidc.clean_session()
        return apache.HTTP_BAD_REQUEST

    req.log_error(
        "%s - Basic Http Authorization header provided %s " % (base_log, auth),
        apache.APLOG_INFO)

    if auth[0] == "BASIC":
        # if user already authentified
        userSession = session.get("user")
        userPassword = oidc.decode_basic_authorization(auth[1])
        if not userPassword:
            oidc.clean_session()
            return oidc.handle_unauthorized()

        (username, _) = userPassword
        if isUserSessionEqualUserAuth(username, userSession):
            req.log_error(
                "%s - User `%s` already authentificated " %
                (base_log, userSession), apache.APLOG_INFO)
            return oidc.handle_existing_session(userPassword)
        else:
            req.log_error("%s - New connection " % (base_log),
                          apache.APLOG_INFO)
            return oidc.handle_basic(userPassword)
    elif auth[0] == "BEARER":
        #return oidc.handle_bearer()
        return oidc.handle_unauthorized()
    else:
        oidc.clean_session()
        return apache.HTTP_BAD_REQUEST
