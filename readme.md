implementation of https://tools.ietf.org/html/rfc6238

<b> Usage </b>

```
secret =  b"Hello there sunshine"
// initalise class
totpgen = TOHOTP(digits= 6, digestmod="sha512")
// generate passcode
code = (totpgen.totp(secret))
// True
print(totpgen.verify(secret, code))
```
