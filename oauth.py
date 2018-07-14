import json
from functools import wraps
from urllib.parse import urlencode

import requests
from flask import Flask, request, current_app, session, redirect, g, jsonify

# ==== Constants ====

_config_key = 'OAUTH'
_request_user_key = 'oauth_user'
_session_uid_key = 'uid'
_session_access_token_key = 'access_token'


# ==== Exceptions ====

class OAuthError(Exception):
    def __init__(self, msg, detail=None):
        self.msg = msg
        self.detail = detail


class OAuthRequired(OAuthError):
    def __init__(self):
        super(OAuthRequired, self).__init__('authentication required')


class OAuthRequestError(OAuthError):
    pass


class OAuthAPIError(OAuthError):
    pass


class OAuthResultError(OAuthError):
    pass


# ==== Model classes ====

class User:
    def __init__(self, _id, name, email, nickname, avatar):
        self.id = _id
        self.name = name
        self.email = email
        self.nickname = nickname
        self.avatar = avatar
        self.groups = []


class Group:
    def __init__(self, _id, name, description):
        self.id = _id
        self.name = name
        self.description = description


# ==== Helper functions ====

def _error_html(msg, detail=None):
    if detail is None:
        detail = ''
    return "<html><body><h1>%s</h1><p>%s</p></body></html>" % (str(msg), str(detail))


def _preferred_mime():
    mimes = request.accept_mimetypes
    for mime in mimes:
        if mime[0] == 'text/html':
            return mime[0]
        if mime[0] == 'application/json':
            return mime[0]
    return 'text/html'


def _build_redirect_url():
    config = current_app.config.get(_config_key)
    config_server = config['server']
    config_client = config['client']
    params = {
        'client_id': config_client['id'],
        'redirect_url': config_client['redirect_url']
    }
    redirect_url = config_server['url'] + config_server['connect_page']
    return redirect_url + '?' + urlencode(params)


def _build_error_output(error: OAuthError):
    mime = _preferred_mime()
    redirect_url = _build_redirect_url()
    if isinstance(error, (OAuthRequired, OAuthRequestError)):
        if mime == 'text/html':
            return redirect(redirect_url)
        else:
            return jsonify(msg=error.msg, detail=error.detail, redirect_url=redirect_url), 403
    else:
        if mime == 'text/html':
            return _error_html(error.msg, error.detail), 500
        else:
            return jsonify(msg=error.msg, detail=error.detail, redirect_url=redirect_url), 500


# ==== Parsers ====

def _parse_response_error(response):
    try:
        data = json.loads(response.text)
        msg = data.get('msg')  # check if it has expected error message format
        if int(response.status_code / 100) == 4:  # 4xx
            return OAuthRequestError(msg=msg, detail=data.get('detail'))
        return OAuthAPIError(msg=msg, detail=data.get('detail'))
    except (ValueError, KeyError):
        return OAuthAPIError(msg='Status %d' % response.status_code, detail=response.text)


def _parse_user(_dict):
    if not _dict:
        raise OAuthResultError('empty user body')
    user = User(_dict.get('id'), _dict.get('name'), _dict.get('email'), _dict.get('nickname'), _dict.get('avatar'))
    if user.id is None:
        raise OAuthResultError('user id is missing')
    if type(user.id) != int:
        raise OAuthResultError('user id should be an integer')
    if not user.name:
        raise OAuthResultError('user name is missing or empty')
    if not user.email:
        raise OAuthResultError('user email is missing or empty')
    group_dicts = _dict.get('groups')
    for group_dict in group_dicts:
        user.groups.append(_parse_group(group_dict))
    return user


def _parse_group(_dict):
    if not _dict:
        raise OAuthResultError('empty group body')
    group = Group(_dict.get('id'), _dict.get('name'), _dict.get('description'))
    if group.id is None:
        raise OAuthResultError('group id is missing')
    if type(group.id) != int:
        raise OAuthResultError('group id should be an integer')
    if not group.name:
        raise OAuthResultError('group name is missing or empty')
    return group


# ==== API requests ====

def _request_oauth_user(access_token):
    config = current_app.config.get(_config_key)
    config_server = config['server']

    try:
        response = requests.get(config_server['url'] + config_server['profile_api'], {'oauth_token': access_token})
    except IOError:
        raise OAuthAPIError('failed to access OAuth API')

    if response.status_code != 200:
        raise _parse_response_error(response)
    try:
        _dict = response.json()
    except ValueError:
        raise OAuthResultError('invalid data format (user profile)')
    return _parse_user(_dict)


def _request_access_token(authorization_token):
    config = current_app.config.get(_config_key)
    config_server = config['server']
    config_client = config['client']

    params = {
        'client_id': config_client['id'],
        'client_secret': config_client['secret'],
        'redirect_url': config_client['redirect_url'],
        'token': authorization_token
    }

    try:
        response = requests.post(config_server['url'] + config_server['token_api'], params)
    except IOError:
        raise OAuthAPIError('failed to access OAuth API')

    if response.status_code != 200:
        raise _parse_response_error(response)
    try:
        data = response.json()
    except ValueError:
        raise OAuthResultError('invalid data format (token)')

    token = data.get('access_token')
    if not token:
        raise OAuthResultError('access_token is missing or empty')


# ==== OAuth callback ====

def _oauth_callback():
    args = request.args
    token = args.get('token')
    try:
        access_token = _request_access_token(token)
        user = _request_oauth_user(access_token)

        session[_session_uid_key] = user.id
        session[_session_access_token_key] = access_token
        return redirect('/')
    except OAuthError as e:
        return _build_error_output(e)


# ==== public decorators ====

def requires_login(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        config = current_app.config.get(_config_key)

        # if disabled
        if not config.get('enabled'):
            return f(*args, **kwargs)

        # if need real ip (when using a reverse-proxy like nginx)
        if config.get('resolve_real_ip'):
            ip = request.environ.get('HTTP_X_FORWARDED_FOR') or \
                 request.environ.get('HTTP_X_REAL_IP') or \
                 request.remote_addr
        else:
            ip = request.remote_addr

        # if whitelisted
        whitelist = config.get('whitelist')
        if whitelist and ip in whitelist:
            return f(*args, **kwargs)

        try:
            get_user()
            return f(*args, **kwargs)
        except OAuthError as e:
            return _build_error_output(e)

    return wrapped


# ==== public functions ====

def get_uid() -> [int, None]:
    """
    Get UID stored in session.
    """
    return session.get(_session_uid_key)


def get_user() -> [User, None]:
    """
    Get User with access token stored in session.

    Because this involves remote API access, it could be slow and may throw exceptions defined in this module.
    The retrieved User will be temporarily cached in the request context, so any subsequent calls within the same
    request context will not trigger the API access.
    """
    user = g.get(_request_user_key)
    if user is not None:
        return user
    uid = get_uid()
    if uid is None:
        clear_user()
        raise OAuthRequired()
    access_token = session.get(_session_access_token_key)
    if access_token is None:
        clear_user()
        raise OAuthRequired()
    user = _request_oauth_user(access_token)
    setattr(g, _request_user_key, user)
    return user


def clear_user() -> None:
    """
    Remove all the OAuth data in session.
    """
    if _request_user_key in g:
        g.pop(_request_user_key)
    if _session_uid_key in session:
        del session[_session_uid_key]
    if _session_access_token_key in session:
        del session[_session_access_token_key]


def init_app(app: Flask, config_file: str = 'oauth.config.json') -> None:
    """
    Initialize OAuth configurations and callbacks in the provided Flask app
    :param app: Your Flask app
    :param config_file: The path to a configuration file for OAuth
    """
    with open(config_file) as f:
        config = json.load(f)
        app.config[_config_key] = config
    app.add_url_rule(config['client']['callback_path'], None, _oauth_callback)

# FIXME infinite redirect
# FIXME 'null' state parameter
# TODO connect via API?
# TODO automatically update access token?
