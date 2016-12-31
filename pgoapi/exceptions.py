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


class PgoapiError(Exception):
    """Any custom exception in this module"""

class HashServerException(PgoapiError):
    """Parent class of all hashing server errors"""


class AuthException(PgoapiError):
    """Raised when logging in fails"""

class InvalidCredentialsException(AuthException, ValueError):
    """Raised when the username, password, or provider are empty/invalid"""


class AuthTokenExpiredException(PgoapiError):
    """Raised when your auth token has expired (code 102)"""


class BadRequestException(PgoapiError):
    """Raised when HTTP code 400 is returned"""

class BadHashRequestException(BadRequestException):
    """Raised when hashing server returns code 400"""


class BannedAccountException(PgoapiError):
    """Raised when an account is banned"""


class MalformedResponseException(PgoapiError):
    """Raised when the response is empty or not in an expected format"""

class MalformedNianticResponseException(PgoapiError):
    """Raised when a Niantic response is empty or not in an expected format"""

class MalformedHashResponseException(MalformedResponseException, HashServerException):
    """Raised when the response from the hash server cannot be parsed."""


class NoPlayerPositionSetException(PgoapiError, ValueError):
    """Raised when either lat or lng is None"""


class NotLoggedInException(PgoapiError):
    """Raised when attempting to make a request while not authenticated"""


class ServerBusyOrOfflineException(PgoapiError):
    """Raised when unable to establish a connection with a server"""

class NianticOfflineException(ServerBusyOrOfflineException):
    """Raised when unable to establish a conection with Niantic"""

class HashingOfflineException(ServerBusyOrOfflineException, HashServerException):
    """Raised when unable to establish a conection with the hashing server"""


class PleaseInstallProtobufVersion3(PgoapiError):
    """Raised when Protobuf is unavailable or too old"""


class ServerSideAccessForbiddenException(PgoapiError):
    """Raised when access to a server is forbidden"""

class NianticIPBannedException(ServerSideAccessForbiddenException):
    """Raised when Niantic returns a 403, meaning your IP is probably banned"""

class HashingForbiddenException(ServerSideAccessForbiddenException, HashServerException):
    """Raised when the hashing server returns 401 or 403"""


class ServerSideRequestThrottlingException(PgoapiError):
    """Raised when too many requests were made in a short period"""

class NianticThrottlingException(ServerSideRequestThrottlingException):
    """Raised when too many requests to Niantic were made in a short period"""

class HashingQuotaExceededException(ServerSideRequestThrottlingException, HashServerException):
    """Raised when you exceed your hashing server quota"""


class UnexpectedResponseException(PgoapiError):
    """Raised when an unhandled HTTP status code is received"""

class UnexpectedHashResponseException(UnexpectedResponseException, HashServerException):
    """Raised when an unhandled HTTP code is received from the hash server"""


class ServerApiEndpointRedirectException(PgoapiError):
    """Raised when the API redirects you to another endpoint"""
    def __init__(self):
        self._api_endpoint = None

    def get_redirected_endpoint(self):
        return self._api_endpoint

    def set_redirected_endpoint(self, api_endpoint):
        self._api_endpoint = api_endpoint
