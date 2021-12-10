# -*- coding: utf8 -*-
__author__ = 'Jager'
import sys
import hmac
import hashlib
import base64
import time


class HmacAuth():
     """Generate Hmac (hmac-sha256) authentication header
     :param hmac_user, String, optional, the HMAC account is preset when the class is initialized, which can be overwritten by the function
     :param hmac_secret, String, optional, preset HMAC key when class is initialized, it can be overwritten by function
     :return Class Object
     """
    def __init__(self, hmac_user=None, hmac_secret=None):
        self.hmac_user = hmac_user
        self.hmac_secret = hmac_secret

    def _sha256_digest(self, content):
         """ sha256 calculation content summary
         :param content, String, content
         """
        if sys.version_info.major > 2:
            content_bytes = bytes(content, "utf-8")

        else:
            content_bytes = bytes(content).decode("utf-8")

        content_sha256_digest = hashlib.sha256(content_bytes).digest()
        content_sha256_digest_base64_decode = base64.b64encode(
            content_sha256_digest).decode()
        content_digest = 'SHA-256={}'.format(
            content_sha256_digest_base64_decode)
        return content_digest

    def _hmac_sha256(self, secret, str_to_sign):
         """Generate sha256 encrypted string
         :param secret, String, specify the secret key
         :param str_to_sign, String, assembled data to be signed
         """
        if sys.version_info.major > 2:
            hmac_key = bytes(secret, "utf-8")
            msg_sign = bytes(str_to_sign, "utf-8")

        else:
            hmac_key = bytes(secret)
            msg_sign = bytes(str_to_sign)

        signature = hmac.new(hmac_key, msg_sign,
                             digestmod=hashlib.sha256).digest()
        str_base64 = base64.b64encode(signature).decode()
        return str_base64

    def get_auth_headers(self, hmac_user=None, hmac_secret=None, body=""):
         """Get Hmac authentication header
         :param String, optional, specify the Hmac account, you can override the Hmac account preset by the class
         :param String, optional, specify the hmac key, which can override the Hmac key preset by the class
         :param String, optional, specify the body content of the request, it must be passed when the gateway requires the verification of the body, and a null value is passed in for the Get request
         :param Dict, return Hmac authentication header dictionary
         """
        if not hmac_user:
            hmac_user = self.hmac_user

        if not hmac_secret:
            hmac_secret = self.hmac_secret

        # Generate sha256 encrypted string of body
        body_digest = self._sha256_digest(body)

        # Generate the current GMT time, note that the format cannot be changed, it must be like: Wed, 14 Aug 2019 09:09:28 GMT
        gm_time = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())

        # Assemble the data to be signed
        str_to_sign = "date: {}\ndigest: {}".format(gm_time, body_digest)

        # Generate signature
        signature = self._hmac_sha256(hmac_secret, str_to_sign)

        # Assemble headers
        headers = {}
        headers["Authorization"] = (
            'hmac username="{}", algorithm="hmac-sha256", headers="date digest",'
            'signature="{}"'.format(hmac_user, signature))
        headers["Digest"] = body_digest
        headers["Date"] = gm_time
        return headers
