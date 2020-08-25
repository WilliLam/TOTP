implementation of https://tools.ietf.org/html/rfc6238

<b> Usage </b>

```
// secret must be in byte form
secret =  b"Hello there sunshine"
// initalise class
// see list of available encryption algorithms in hashlib.algorithms_guaranteed
totpgen = TOHOTP(digits= 6, digestmod="sha512")
// generate passcode
code = (totpgen.totp(secret))
// True
print(totpgen.verify(secret, code))
```
