class HashEngine:
    def __init__(self):
        self.location_hash = None
        self.location_auth_hash = None
        self.request_hashes = []

    def hash(self, timestamp, latitude, longitude, altitude, authticket, sessiondata, requests):
        raise NotImplementedError()

    def get_location_hash(self):
        return self.location_hash
    def get_location_auth_hash(self):
        return self.location_auth_hash
    def get_request_hashes(self):
        return self.request_hashes
