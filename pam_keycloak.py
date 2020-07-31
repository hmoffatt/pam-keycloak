import os.path
activate_this = os.path.join(os.path.dirname(os.path.realpath(__file__)), '.pyvenv/bin/activate_this.py')
exec(compile(open(activate_this).read(), activate_this, 'exec'), dict(__file__=activate_this))

import syslog
from dotenv import dotenv_values
from keycloak import KeycloakOpenID
from keycloak.exceptions import KeycloakError


DEFAULT_USER = "nobody"

syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_AUTH)

options = {}


def parse_options(pamh, argv):
    global options
    for arg in argv[1:]:
        args = arg.split('=')
        if len(args) > 1:
            options[args[0]] = args[1]
        else:
            options[args[0]] = True

    try:
        config_file = options.get('config')
        if config_file:
            if not os.path.isabs(config_file):
                config_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), config_file)
            options.update(dotenv_values(config_file))

    except Exception as e:
        pam_syslog(syslog.LOG_CRIT, pamh, "auth", "failed to read configuration: %s" % e)
        return pamh.PAM_SYSTEM_ERR


def pam_syslog(prio, pamh, choice, message):
    #print("pam_keycloak(%s:%s): %s" % (pamh.service, choice, message))
    syslog.syslog(prio, "pam_keycloak(%s:%s): %s" % (pamh.service, choice, message))


def pam_sm_authenticate(pamh, flags, argv):
    parse_options(pamh, argv)

    try:
        user = pamh.get_user(None)
    except pamh.exception, e:
        return e.pam_result
    if user is None:
        pamh.user = DEFAULT_USER

    try:
        # Configure client
        keycloak_openid = KeycloakOpenID(server_url=options['server_url'],
                                         realm_name=options['realm_name'],
                                         client_id=options['client_id'],
                                         client_secret_key=options['client_secret_key'],
                                         verify=True)

        # Get WellKnow
        config_well_know = keycloak_openid.well_know()

    except KeycloakError, e:
        pam_syslog(syslog.LOG_NOTICE, pamh, "auth", "unable to authenticate for %s: %d %s" % (user, e.response_code, e.error_message))
        return pamh.PAM_AUTHINFO_UNAVAIL

    if pamh.authtok is None:
        passmsg = pamh.Message(pamh.PAM_PROMPT_ECHO_OFF,
                               "Password: ")
        res = pamh.conversation(passmsg)
        pamh.authtok = res.resp

    try:
        token = keycloak_openid.token(user, pamh.authtok)

        # Potentially fetch the user info and check for specific claims here:
        # userinfo = keycloak_openid.userinfo(token['access_token'])

        return pamh.PAM_SUCCESS

    except KeycloakError as e:
        pam_syslog(syslog.LOG_NOTICE, pamh, "auth", "authentication failure for %s: %d %s" % (user, e.response_code, e.error_message))

        if e.response_code == 401:
            return pamh.PAM_AUTH_ERR

        return pamh.PAM_AUTHINFO_UNAVAIL

    return pamh.PAM_AUTH_ERR


def pam_sm_setcred(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_acct_mgmt(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_open_session(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_close_session(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_chauthtok(pamh, flags, argv):
    return pamh.PAM_SUCCESS
