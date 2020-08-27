from totp.main import TOTP
from time import sleep

def test_len_totp():
    test1 = TOTP(digits=6, digestmod="sha1")
    assert len(str(test1.totp(b"whatever", window=30))) == 6
    test1 = TOTP(digits=6, digestmod="sha256")
    assert len(str(test1.totp(b"whatever", window=30))) == 6
    test1 = TOTP(digits=10, digestmod="sha512")
    assert len(str(test1.totp(b"whatever", window=30))) == 10

def test_verify_totp():
    test1 = TOTP(digits=6, digestmod="sha256")
    passcode = test1.totp(b"213124213123123123231232", window = 3)
    sleep(1)
    assert test1.verify(b"213124213123123123231232", passcode,window=3, allowed_steps=3)
    sleep(6)
    assert test1.verify(b"213124213123123123231232", passcode, window=3, allowed_steps=1) == False
