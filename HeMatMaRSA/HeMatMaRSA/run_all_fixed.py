# run_all_fixed.py
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("=" * 60)
print("RSA TEST SUITE - FIXED VERSION")
print("=" * 60)

def run_test(name, test_func):
    try:
        result = test_func()
        print(f"✅ {name}: PASSED")
        return True
    except Exception as e:
        print(f"❌ {name}: FAILED - {e}")
        return False

# Import và test từng phần
try:
    # Test 1: RSA Core
    print("\n1. Testing RSA Core...")
    from core.rsa_core import RSAKeyPair
    import secrets
    
    def test_rsa_core():
        rsa = RSAKeyPair().generate(2048)
        m = 123456789
        c = rsa.encrypt_int(m)
        m2 = rsa.decrypt_int(c)
        assert m == m2
        return True
    
    run_test("RSA Core", test_rsa_core)
    
    # Test 2: OAEP
    print("\n2. Testing OAEP...")
    from core.oaep import oaep_encode, oaep_decode
    
    def test_oaep():
        msg = b"hello rsa"
        k = 256
        em = oaep_encode(msg, k)
        decoded = oaep_decode(em, k)
        assert decoded == msg
        return True
    
    run_test("OAEP", test_oaep)
    
    # Test 3: Signature
    print("\n3. Testing Signatures...")
    from core.signature import RSASSA_PKCS1v15
    
    def test_signature():
        rsa = RSAKeyPair().generate(2048)
        msg = b"Test message"
        sig = RSASSA_PKCS1v15.sign(msg, rsa)
        verified = RSASSA_PKCS1v15.verify(msg, sig, rsa)
        assert verified
        return True
    
    run_test("Signature", test_signature)
    
    print("\n" + "=" * 60)
    print("All manual tests completed!")
    print("=" * 60)
    
except Exception as e:
    print(f"\n❌ Setup failed: {e}")