"""
pgoapi - Pokemon Go API
Copyright (c) 2016 tjado <https://github.com/tejado>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
OR OTHER DEALINGS IN THE SOFTWARE.

Author: tjado <https://github.com/tejado>
"""

from __future__ import absolute_import
from future.standard_library import install_aliases
install_aliases()

import requests

from urllib.parse import parse_qs, urlsplit
from six import string_types

from pgoapi.auth import Auth
from pgoapi.utilities import get_time
from pgoapi.exceptions import AuthException, AuthTimeoutException, InvalidCredentialsException

from requests.exceptions import RequestException, Timeout

class AuthPtc(Auth):

    PTC_LOGIN_URL1 = 'https://sso.pokemon.com/sso/oauth2.0/authorize?client_id=mobile-app_pokemon-go&redirect_uri=https%3A%2F%2Fwww.nianticlabs.com%2Fpokemongo%2Ferror'
    PTC_LOGIN_URL2 = 'https://sso.pokemon.com/sso/login?service=http%3A%2F%2Fsso.pokemon.com%2Fsso%2Foauth2.0%2FcallbackAuthorize'
    PTC_LOGIN_OAUTH = 'https://sso.pokemon.com/sso/oauth2.0/accessToken'
    PTC_LOGIN_CLIENT_SECRET = 'w8ScCUXJQc6kXKw8FiOhd8Fixzht18Dq3PEVkUCP5ZPxtgyWsbTvWHFLm2wNY0JR'

    def __init__(self, username=None, password=None, user_agent=None, timeout=None):
        Auth.__init__(self)

        self._auth_provider = 'ptc'

        self._session = requests.session()
        self._session.headers = {'User-Agent': user_agent or 'pokemongo/1 CFNetwork/811.4.18 Darwin/16.5.0', 'Host': 'sso.pokemon.com', 'X-Unity-Version': '2017.1.2f1'}
        self._username = username
        self._password = password
        self.timeout = timeout or 15

    def set_proxy(self, proxy_config):
        self._session.proxies = proxy_config

    def user_login(self, username=None, password=None, retry=True):
        self._username = username or self._username
        self._password = password or self._password
        if not isinstance(self._username, string_types) or not isinstance(self._password, string_types):
            raise InvalidCredentialsException("Username/password not correctly specified")

        self.log.info('PTC User Login for: {}'.format(self._username))
        self._session.cookies.clear()
        now = get_time()

        try:
            r = self._session.get(self.PTC_LOGIN_URL1, timeout=self.timeout)
        except Timeout:
            raise AuthTimeoutException('Auth GET timed out.')
        except RequestException as e:
            raise AuthException('Caught RequestException: {}'.format(e))

        try:
            data = r.json()
            data.update({
                '_eventId': 'submit',
                'username': self._username,
                'password': self._password,
            })
        except (ValueError, AttributeError) as e:
            self.log.error('PTC User Login Error - invalid JSON response: {}'.format(e))
            raise AuthException('Invalid JSON response: {}'.format(e))

        try:
            r = self._session.post(self.PTC_LOGIN_URL2, data=data, timeout=self.timeout, allow_redirects=False)
        except Timeout:
            raise AuthTimeoutException('Auth POST timed out.')
        except RequestException as e:
            raise AuthException('Caught RequestException: {}'.format(e))

        try:
            qs = parse_qs(urlsplit(r.headers['Location'])[3])
            self._refresh_token = qs.get('ticket')[0]
        except Exception as e:
            raise AuthException('Could not retrieve token! {}'.format(e))

        self._access_token = self._session.cookies.get('CASTGC')
        if self._access_token:
            self._login = True
            self._access_token_expiry = int(now) + 7200
            self.log.info('PTC User Login successful.')
        elif self._refresh_token and retry:
            self.get_access_token()
        else:
            self._login = False
            raise AuthException("Could not retrieve a PTC Access Token")
        return self._login

    def set_refresh_token(self, refresh_token):
        self.log.info('PTC Refresh Token provided by user')
        self._refresh_token = refresh_token

    def get_access_token(self, force_refresh=False):
        token_validity = self.check_access_token()

        if token_validity is True and force_refresh is False:
            self.log.debug('Using cached PTC Access Token')
            return self._access_token
        else:
            if force_refresh:
                self.log.info('Forced request of PTC Access Token!')
            else:
                self.log.info('Request PTC Access Token...')

            data = {
                'client_id': 'mobile-app_pokemon-go',
                'redirect_uri': 'https://www.nianticlabs.com/pokemongo/error',
                'client_secret': self.PTC_LOGIN_CLIENT_SECRET,
                'grant_type': 'refresh_token',
                'code': self._refresh_token,
            }

            try:
                r = self._session.post(self.PTC_LOGIN_OAUTH, data=data, timeout=self.timeout)
            except Timeout:
                raise AuthTimeoutException('Auth POST timed out.')
            except RequestException as e:
                raise AuthException('Caught RequestException: {}'.format(e))

            token_data = parse_qs(r.text)

            access_token = token_data.get('access_token')
            if access_token is not None:
                self._access_token = access_token[0]

                # set expiration to an hour less than value received because Pokemon OAuth
                # login servers return an access token with an explicit expiry time of
                # three hours, however, the token stops being valid after two hours.
                # See issue #86
                expires = int(token_data.get('expires', [0])[0]) - 3600
                if expires > 0:
                    self._access_token_expiry = expires + get_time()
                else:
                    self._access_token_expiry = 0

                self._login = True

                self.log.info('PTC Access Token successfully retrieved.')
                self.log.debug('PTC Access Token: {}'.format(self._access_token))
            else:
                self._access_token = None
                self._login = False
                if force_refresh:
                    self.log.info('Reauthenticating with refresh token failed, using credentials instead.')
                    return self.user_login(retry=False)
                raise AuthException("Could not retrieve a PTC Access Token")
