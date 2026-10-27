import unittest
from protocol import seal,open_seal
class ProtocolTest(unittest.TestCase):
    def test_authenticated_encryption(self):
        key=b'SESSIONKEY123456'
        packet=seal({'text':'HALO BOB'},key)
        self.assertEqual(open_seal(packet,key)['text'],'HALO BOB')
        packet['tag']='00'*32
        with self.assertRaises(ValueError):open_seal(packet,key)
if __name__=='__main__':unittest.main()
