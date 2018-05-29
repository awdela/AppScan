import json
import requests
import pdb
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS = 'ALL'

class Request(object):
    def __init__(self,base_url,headers):
        self.base_url=base_url
        self.headers=headers

    def get(self,url):
        try:
            response = requests.get(self.base_url+url,headers=self.headers,timeout=30,verify=False)
            result = json.loads(response.content)
            return result
        except Exception as e:
            print ('requests has error',e)
            raise e
    
    def post(self,url,data):
        try:
            response = requests.post(self.base_url+url,data,headers=self.headers,timeout=30,verify=False)
            result = response.content
            if result == '':
                return result
            else:
                result = json.loads(result)
                return result
        except Exception as e:
            print ('requests has error',e)
            raise e
    
    def post2(self,url,data):
        try:
            response = requests.post(self.base_url+url,data,headers=self.headers,timeout=30,verify=False)
            return response
        except Exception as e:
            print ('requests has error',e)
            raise e
