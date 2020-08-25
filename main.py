import hashlib
import hmac
import time

class TOHOTP:
    def __init__(self, digits = 6, digestmod="sha1"):
        """

        :param key:  shared key/keygen
        :param msg:  counter
        :param digestmod: check hashlib.algorithms_guaranteed or hashlib.algorithms_available -
        defaults to the hmac sha-1 implementation
        """
        # self.key = key
        self.digits = digits
        self.digestmod = digestmod

    def truncate(self, digest, digits):
        Offset= digest[-1] & 0x0f
        P =((digest[Offset] & 0x7f) << 24 | (digest[Offset+1] & 0xff) << 16 | (digest[Offset+2] & 0xff) << 8 | \
            (digest[Offset+3] & 0xff))
        return P % (10**digits)

    def hotp(self, k, c = "000000000000000"):
        if type(c) == str:
            c = bytes.fromhex(c)
        # hmac.digest(k, msg=c, digest="sha512")
        # print(self, c)
        nhmac = hmac.new(key = k, msg = c, digestmod=self.digestmod)
        # print("h2", (hashlib.sha3_512(self).digest()), "size", hashlib.sha3_512(self).digest_size, )
        return self.truncate(nhmac.digest(), self.digits)



    def totp(self,  k, window= 30):
        """
        based on https://tools.ietf.org/html/rfc6238#page-4
        secret string : key to generate password from
        digits int : length of password to generate
        window int : how long before step(c) increments
        """
        # c is counter in hotp - check https://tools.ietf.org/html/rfc4226#page-5
        c = hex(int(time.time() // window))[2:]
        while len(c) < 16:
            c = "0" + c
        return self.hotp(k, c)

    def verify(self, k, code, window=30, allowed_steps = 2):
        """
        checks if the code is valid, max time allowed being window*allowed_steps
        :param k: secret
        :param code: number from request totp
        :param window: n seconds for each step
        :param allowed_steps: n steps before to match
        :return: boolean depending on verify successful
        """
        for i in range(0, allowed_steps+1):
            c = hex(int((time.time() - i*window) // window))[2:]
            while len(c) < 16:
                c = "0" + c
            if code == self.hotp(k, c):
                return True
        return False


