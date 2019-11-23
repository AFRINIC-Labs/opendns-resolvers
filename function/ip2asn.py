import requests
import time
import json
from pprint import pprint

__version__ = '1.1'

class IP2ASN:
    """IP2ASN Class object intantiation.
        Args:
            sourceapp: Define the app name to beb used for querying Stat.ripe Data API
    """

    def __init__(self, sourceapp: str="afrinic-intertnship-research"):
        self.sourceapp = sourceapp
        self.ripe_url = 'https://stat.ripe.net/data/network-info/data.json?sourceapp=' + self.sourceapp + '&resource='

    def get_asn_ripe(self, ip_addr: str):
        get_request = requests.get(self.ripe_url + ip_addr).content
        #print("Debugging -- {}".format(get_request))
        get_req = json.loads(get_request)
        if get_req['data']['asns']:
            result = ','.join(get_req['data']['asns'])
        else:
            result = "Unknown"
        return result
