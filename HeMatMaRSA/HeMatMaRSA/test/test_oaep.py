from core.oaep import oaep_encode, oaep_decode

def test_oaep():
    msg = b"hello rsa"
    k = 256
    em = oaep_encode(msg, k)
    assert oaep_decode(em, k) == msg
