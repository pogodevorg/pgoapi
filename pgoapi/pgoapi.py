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

import logging
import requests
import time

from . import __title__, __version__, __copyright__
from pgoapi.rpc_api import RpcApi
from pgoapi.auth_ptc import AuthPtc
from pgoapi.auth_google import AuthGoogle
from pgoapi.utilities import parse_api_endpoint
from pgoapi.exceptions import AuthException, AuthTokenExpiredException, BadRequestException, BannedAccountException, InvalidCredentialsException, NoPlayerPositionSetException, NotLoggedInException, ServerApiEndpointRedirectException, ServerBusyOrOfflineException, UnexpectedResponseException

from . import protos
from pogoprotos.networking.requests.request_type_pb2 import RequestType
from pogoprotos.networking.platform.platform_request_type_pb2 import PlatformRequestType

logger = logging.getLogger(__name__)


class PGoApi:

    def __init__(self, provider=None, oauth2_refresh_token=None, username=None, password=None, position_lat=None, position_lng=None, position_alt=None, proxy_config=None, device_info=None):
        self.set_logger()
        self.log.info('%s v%s - %s', __title__, __version__, __copyright__)

        self._auth_provider = None
        if provider is not None and ((username is not None and password is not None) or (oauth2_refresh_token is not None)):
            self.set_authentication(provider, oauth2_refresh_token, username, password, proxy_config)

        self.set_api_endpoint("pgorelease.nianticlabs.com/plfe")

        self._position_lat = position_lat
        self._position_lng = position_lng
        self._position_alt = position_alt

        self._hash_server_token = None

        self._session = requests.session()
        self._session.headers.update({'User-Agent': 'Niantic App'})
        self._session.verify = True

        if proxy_config is not None:
            self._session.proxies = proxy_config

        self.device_info = device_info

    def set_logger(self, logger=None):
        self.log = logger or logging.getLogger(__name__)

    @staticmethod
    def get_api_version():
        return 8700

    def set_authentication(self, provider=None, oauth2_refresh_token=None, username=None, password=None, proxy_config=None, user_agent=None, timeout=None):
        if provider == 'ptc':
            self._auth_provider = AuthPtc(user_agent=user_agent, timeout=timeout)
        elif provider == 'google':
            self._auth_provider = AuthGoogle()
        elif provider is None:
            self._auth_provider = None
        else:
            raise InvalidCredentialsException("Invalid authentication provider - only ptc/google available.")

        self.log.debug('Auth provider: {}'.format(provider))

        if proxy_config:
            self._auth_provider.set_proxy(proxy_config)

        if oauth2_refresh_token is not None:
            self._auth_provider.set_refresh_token(oauth2_refresh_token)
        elif username and password:
            if not self._auth_provider.user_login(username, password):
                raise AuthException("User login failed!")
        else:
            raise InvalidCredentialsException("Invalid Credential Input - Please provide username/password or an oauth2 refresh token")

    def get_position(self):
        return (self._position_lat, self._position_lng, self._position_alt)

    def set_position(self, lat, lng, alt=None):
        self.log.debug('Set Position - Lat: %s Long: %s Alt: %s', lat, lng, alt)

        self._position_lat = lat
        self._position_lng = lng
        self._position_alt = alt

    def set_proxy(self, proxy_config):
        self._session.proxies = proxy_config

    def get_api_endpoint(self):
        return self._api_endpoint

    def set_api_endpoint(self, api_url):
        if api_url.startswith("https"):
            self._api_endpoint = api_url
        else:
            self._api_endpoint = parse_api_endpoint(api_url)

    def get_auth_provider(self):
        return self._auth_provider

    def create_request(self):
        request = PGoApiRequest(self, self._position_lat, self._position_lng,
                                self._position_alt, self.device_info)
        return request

    def activate_hash_server(self, hash_server_token):
        self._hash_server_token = hash_server_token

    def get_hash_server_token(self):
        return self._hash_server_token

    def __getattr__(self, func):
        def function(**kwargs):
            request = self.create_request()
            getattr(request, func)(_call_direct=True, **kwargs )
            return request.call()

        if func.upper() in RequestType.keys():
            return function
        else:
            raise AttributeError

    def app_simulation_login(self):
        self.log.info('Starting RPC login sequence (iOS app simulation)')

        # Send empty initial request
        request = self.create_request()
        response = request.call()
        
        time.sleep(1.5)
        
        # Send GET_PLAYER only
        request = self.create_request()
        request.get_player(player_locale = {'country': 'US', 'language': 'en', 'timezone': 'America/Chicago'})
        response = request.call()

        if response.get('responses', {}).get('GET_PLAYER', {}).get('banned', False):
            raise BannedAccountException

        time.sleep(1.5)

        request = self.create_request()
        request.download_remote_config_version(platform=1, app_version=self.get_api_version())
        request.check_challenge()
        request.get_hatched_eggs()
        request.get_inventory()
        request.check_awarded_badges()
        request.download_settings()
        response = request.call()

        self.log.info('Finished RPC login sequence (iOS app simulation)')

        return response

    """
    The login function is not needed anymore but still in the code for backward compatibility"
    """
    def login(self, provider, username, password, lat=None, lng=None, alt=None, app_simulation=True):

        if lat and lng:
            self._position_lat = lat
            self._position_lng = lng
        if alt:
            self._position_alt = alt

        try:
            self.set_authentication(provider, username=username, password=password)
        except AuthException as e:
            self.log.error('Login process failed: %s', e)
            return False

        if app_simulation:
            response = self.app_simulation_login()
        else:
            self.log.info('Starting minimal RPC login sequence')
            response = self.get_player()
            self.log.info('Finished minimal RPC login sequence')

        if not response:
            self.log.info('Login failed!')
            return False

        self.log.info('Login process completed')

        return True


class PGoApiRequest:

    def __init__(self, parent, position_lat, position_lng, position_alt,
                 device_info=None):
        self.log = logging.getLogger(__name__)

        self.__parent__ = parent

        """ Inherit necessary parameters from parent """
        self._api_endpoint = self.__parent__.get_api_endpoint()
        self._auth_provider = self.__parent__.get_auth_provider()

        self._position_lat = position_lat
        self._position_lng = position_lng
        self._position_alt = position_alt

        self._req_method_list = []
        self._req_platform_list = []
        self.device_info = device_info

    def call(self, use_dict = True):
        if (self._position_lat is None) or (self._position_lng is None):
            raise NoPlayerPositionSetException

        if self._auth_provider is None or not self._auth_provider.is_login():
            self.log.info('Not logged in')
            raise NotLoggedInException

        request = RpcApi(self._auth_provider, self.device_info)
        request._session = self.__parent__._session

        hash_server_token = self.__parent__.get_hash_server_token()
        request.activate_hash_server(hash_server_token)

        response = None
        execute = True
        
        while execute:
            execute = False

            try:
                response = request.request(self._api_endpoint, self._req_method_list, self._req_platform_list, self.get_position(), use_dict)
            except AuthTokenExpiredException as e:
                """
                This exception only occures if the OAUTH service provider (google/ptc) didn't send any expiration date
                so that we are assuming, that the access_token is always valid until the API server states differently.
                """
                try:
                    self.log.info('Access Token rejected! Requesting new one...')
                    self._auth_provider.get_access_token(force_refresh=True)
                except Exception as e:
                    error = 'Reauthentication failed: {}'.format(e)
                    self.log.error(error)
                    raise NotLoggedInException(error)

                request.request_proto = None  # reset request and rebuild
                execute = True  # reexecute the call
            except ServerApiEndpointRedirectException as e:
                self.log.info('API Endpoint redirect... re-execution of call')
                new_api_endpoint = e.get_redirected_endpoint()

                self._api_endpoint = parse_api_endpoint(new_api_endpoint)
                self.__parent__.set_api_endpoint(self._api_endpoint)

                execute = True  # reexecute the call

        # cleanup after call execution
        self._req_method_list = []

        return response

    def list_curr_methods(self):
        for i in self._req_method_list:
            print("{} ({})".format(RequestType.Name(i), i))

    def get_position(self):
        return (self._position_lat, self._position_lng, self._position_alt)

    def set_position(self, lat, lng, alt=None):
        self.log.debug('Set Position - Lat: %s Long: %s Alt: %s', lat, lng, alt)

        self._position_lat = lat
        self._position_lng = lng
        self._position_alt = alt

    def __getattr__(self, func):
        def add_request(**kwargs):

                if '_call_direct' in kwargs:
                    del kwargs['_call_direct']
                    self.log.info('Creating a new direct request...')
                elif not self._req_method_list:
                    self.log.info('Creating a new request...')

                name = func.upper()
                if kwargs:
                    self._req_method_list.append((RequestType.Value(name), kwargs))
                    self.log.info("Adding '%s' to RPC request including arguments", name)
                    self.log.debug("Arguments of '%s': \n\r%s", name, kwargs)
                else:
                    self._req_method_list.append((RequestType.Value(name), None))
                    self.log.info("Adding '%s' to RPC request", name)

                return self

        def add_platform(**kwargs):

            if '_call_direct' in kwargs:
                del kwargs['_call_direct']

            name = func.upper()
            if kwargs:
                self._req_platform_list.append((PlatformRequestType.Value(name), kwargs))
                self.log.info("Adding '%s' to RPC request including arguments", name)
                self.log.debug("Arguments of '%s': \n\r%s", name, kwargs)
            else:
                self._req_platform_list.append((PlatformRequestType.Value(name), None))
                self.log.info("Adding '%s' to RPC request", name)

            return self    

        name = func.upper()
        if name in RequestType.keys():
            return add_request
        elif name in PlatformRequestType.keys():
            return add_platform
        else:
            raise AttributeError
