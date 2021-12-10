# -*- coding: utf8 -*-
import requests
from hmac_auth import HmacAuth

if __name__ == "__main__":
    # Modify according to actual situation
    USERNAME = "<HMAC account>"
    SECRET = "<HMAC secret>"
    API_URL = "<Interface address with hmac authentication>"
    param = {"xxx": {"xxxx": "xxx"}}

    # Method 1: Set the account secret when initializing the class
    hmac_auth = HmacAuth(hmac_user=USERNAME, hmac_secret=SECRET)
    headers = hmac_auth.get_auth_headers()

    # Method 2: Set the account secret when generating the header
    # hmac_auth = HmacAuth()
    # headers = hmac_auth.get_auth_headers(hmac_user=USERNAME, hmac_secret=SECRET)

    resp = requests.post(url=API_URL, json=param, headers=headers)

    if resp.status_code == 200:
        exit("Test OK!")

    else:
        print(headers)
        print(resp.text)
        exit("Test Failed!")
