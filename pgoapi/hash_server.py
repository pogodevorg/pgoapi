from __future__ import absolute_import

import ctypes
import base64
import requests

from pgoapi.hash_engine import HashEngine
from pgoapi.exceptions import BadHashRequestException, HashingOfflineException, HashingQuotaExceededException, HashingTimeoutException, MalformedHashResponseException, TempHashingBanException, UnexpectedHashResponseException

class HashServer(HashEngine):
    _session = requests.session()
    _adapter = requests.adapters.HTTPAdapter(pool_maxsize=150, pool_block=True)
    _session.mount('https://', _adapter)
    _session.verify = True
    _session.headers.update({'User-Agent': 'Python pgoapi @pogodev'})
    endpoint = "https://pokehash.buddyauth.com/api/v121_2/hash"
    status = {}

    def __init__(self, auth_token):
        self.headers = {'content-type': 'application/json', 'Accept' : 'application/json', 'X-AuthToken' : auth_token}

    def hash(self, timestamp, latitude, longitude, altitude, authticket, sessiondata, requestslist):
        self.location_hash = None
        self.location_auth_hash = None
        self.request_hashes = []

        payload = {}
        payload["Timestamp"] = timestamp
        payload["Latitude"] = latitude
        payload["Longitude"] = longitude
        payload["Altitude"] = altitude
        payload["AuthTicket"] = base64.b64encode(authticket).decode('ascii')
        payload["SessionData"] = base64.b64encode(sessiondata).decode('ascii')
        payload["Requests"] = []
        for request in requestslist:
            payload["Requests"].append(base64.b64encode(request.SerializeToString()).decode('ascii'))

        # request hashes from hashing server
        try:
            response = self._session.post(self.endpoint, json=payload, headers=self.headers, timeout=30)
        except requests.exceptions.Timeout:
            raise HashingTimeoutException('Hashing request timed out.')
        except requests.exceptions.ConnectionError as error:
            raise HashingOfflineException(error)

        if response.status_code == 400:
            raise BadHashRequestException("400: Bad request, error: {}".format(response.text))
        elif response.status_code == 403:
            raise TempHashingBanException('Your IP was temporarily banned for sending too many requests with invalid keys')
        elif response.status_code == 429:
            raise HashingQuotaExceededException("429: Request limited, error: {}".format(response.text))
        elif response.status_code in (502, 503, 504):
            raise HashingOfflineException('{} Server Error'.format(response.status_code))
        elif response.status_code != 200:
            error = 'Unexpected HTTP server response - needs 200 got {c}. {t}'.format(
                c=response.status_code, t=response.text)
            raise UnexpectedHashResponseException(error)

        if not response.content:
            raise MalformedHashResponseException('Response was empty')

        headers = response.headers
        try:
            self.status['period'] = int(headers.get('X-RatePeriodEnd'))
            self.status['remaining'] = int(headers.get('X-RateRequestsRemaining'))
            self.status['maximum'] = int(headers.get('X-MaxRequestCount'))
        except TypeError:
            pass

        try:
            response_parsed = response.json()
        except ValueError:
            raise MalformedHashResponseException('Unable to parse JSON from hash server.')

        self.location_auth_hash = ctypes.c_int32(response_parsed['locationAuthHash']).value
        self.location_hash = ctypes.c_int32(response_parsed['locationHash']).value

        for request_hash in response_parsed['requestHashes']:
            self.request_hashes.append(ctypes.c_int64(request_hash).value)
