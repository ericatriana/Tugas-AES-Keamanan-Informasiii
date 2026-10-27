import unittest
from aes import encrypt_block,decrypt_block,cbc_encrypt,cbc_decrypt
class AESTest(unittest.TestCase):
    def test_nist_vector(self):
        k=bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        p=bytes.fromhex('00112233445566778899aabbccddeeff')
        c=bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a')
        self.assertEqual(encrypt_block(p,k),c)
        self.assertEqual(decrypt_block(c,k),p)
    def test_roundtrip(self):
        key=b'SESSIONKEY123456'
        for data in (b'',b'HELLO',b'X'*16,b'Y'*100):
            self.assertEqual(cbc_decrypt(cbc_encrypt(data,key),key),data)
if __name__=='__main__':unittest.main()
