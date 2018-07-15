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
        self.links = {}

    def __repr__(self):
        return '<User %r>' % self.name

    def to_dict(self):
        return dict(id=self.id, name=self.name, email=self.email, nickname=self.nickname, avatar=self.avatar,
                    groups=[group.to_dict() for group in self.groups], links=self.links)


class Group:
    def __init__(self, _id, name, description):
        self.id = _id
        self.name = name
        self.description = description

    def __repr__(self):
        return '<Group %r>' % self.name

    def to_dict(self):
        return dict(id=self.id, name=self.name, description=self.description)


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


def _build_redirect_url(original_path, state):
    config = current_app.config.get(_config_key)
    config_server = config['server']
    config_client = config['client']
    params = {
        'client_id': config_client['id'],
        'redirect_url': config_client['url'] + config_client['callback_path']
    }
    if original_path:
        params['original_path'] = original_path
    if state:
        params['state'] = state
    redirect_url = config_server['url'] + config_server['connect_page']
    return redirect_url + '?' + urlencode(params)


def _build_error_response(error: OAuthError, original_path=None, previous_state=None):
    mime = _preferred_mime()
    if isinstance(error, (OAuthRequired, OAuthRequestError)) \
            and previous_state not in ['new_request', 'request_error']:  # avoid infinite redirect
        if isinstance(error, OAuthRequired):
            state = 'new_request'
        else:
            state = 'request_error'
        redirect_url = _build_redirect_url(original_path=original_path, state=state)
        if mime == 'text/html':
            return redirect(redirect_url)
        else:
            return jsonify(msg=error.msg, detail=error.detail, redirect_url=redirect_url), 401
    else:
        if mime == 'text/html':
            return _error_html(error.msg, error.detail), 500
        else:
            return jsonify(msg=error.msg, detail=error.detail), 500


def _is_oauth_skipped():
    config = current_app.config.get(_config_key)

    # if disabled
    if not config.get('enabled'):
        return True

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
        return True

    return False


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

    config = current_app.config.get(_config_key)
    config_server = config['server']
    server_url = config_server['url']

    # fix prefix for avatars
    if user.avatar and not user.avatar.startswith('http://') and not user.avatar.startswith('https://'):
        user.avatar = server_url + user.avatar

    # add useful links
    links = config_server.get('links')
    for k, v in links.items():
        user.links[k] = server_url + v

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
    if not access_token:
        raise OAuthRequestError('access token is required')

    config = current_app.config.get(_config_key)
    config_server = config['server']

    try:
        response = requests.get(config_server['url'] + config_server['profile_api'], {'oauth_token': access_token})
    except IOError:
        raise OAuthAPIError('failed to access OAuth API (user profile)')

    if response.status_code != 200:
        raise _parse_response_error(response)
    try:
        _dict = response.json()
    except ValueError:
        raise OAuthResultError('invalid data format (user profile)')
    return _parse_user(_dict)


def _request_access_token(authorization_token):
    if not authorization_token:
        raise OAuthRequestError('authorization token is required')

    config = current_app.config.get(_config_key)
    config_server = config['server']
    config_client = config['client']

    params = {
        'client_id': config_client['id'],
        'client_secret': config_client['secret'],
        'redirect_url': config_client['url'] + config_client['callback_path'],
        'token': authorization_token
    }

    try:
        response = requests.post(config_server['url'] + config_server['token_api'], params)
    except IOError:
        raise OAuthAPIError('failed to access OAuth API (access token)')

    if response.status_code != 200:
        raise _parse_response_error(response)
    try:
        data = response.json()
    except ValueError:
        raise OAuthResultError('invalid data format (token)')

    token = data.get('access_token')
    if not token:
        raise OAuthResultError('access_token is missing or empty')
    return token


# ==== OAuth callback ====

def _oauth_callback():
    config = current_app.config.get(_config_key)
    config_client = config['client']

    args = request.args
    token = args.get('token')
    state = args.get('state')
    original_path = args.get('original_path')

    try:
        access_token = _request_access_token(token)
        user = _request_oauth_user(access_token)

        session[_session_uid_key] = user.id
        session[_session_access_token_key] = access_token

        if original_path:
            if original_path[0] != '/':
                original_path = '/' + original_path  # ensure URL to self
        else:
            original_path = '/'
        return redirect(config_client['url'].rstrip('/') + original_path)
    except OAuthError as e:
        return _build_error_response(e, original_path, state)


# ==== public decorators ====

def requires_login(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if _is_oauth_skipped():
            return f(*args, **kwargs)

        try:
            get_user()
            return f(*args, **kwargs)
        except OAuthError as e:
            if _preferred_mime() == 'text/html':
                original_path = request.full_path
            else:
                referrer = request.referrer  # use the referer page rather than the URL for the current request
                config = current_app.config.get(_config_key)
                config_client = config['client']
                client_url_prefix = config_client['url'].rstrip('/')
                if referrer and referrer.startswith(client_url_prefix):
                    original_path = referrer[len(client_url_prefix):]
                else:
                    original_path = None  # cannot find a reliable one
            return _build_error_response(e, original_path)

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

    Call this inside a function protected by @requires_login. Otherwise, you need to handle possible exceptions.
    """
    if _is_oauth_skipped():  # return None only if OAuth is skipped
        return None
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

# TODO connect via API? --> avoid infinite loop && CORS issues
# TODO automatically update access token?
# TODO auto prefix avatar URL?
# TODO fix socket authentication
