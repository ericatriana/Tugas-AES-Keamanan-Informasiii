"""Regression checks for the three documented optional features."""
import socket
import threading
import unittest

from aes import cbc_encrypt, cbc_decrypt
from protocol import seal, open_seal, send
from alice import handshake as alice_handshake
from bob import handshake as bob_handshake, listen as bob_listen
from kdc import handle as kdc_handle

KA = b'ALICEKEY12345678'
KB = b'BOBSECRETKEY1234'


class ExtraFeaturesTest(unittest.TestCase):

    def test_cbc_random_iv(self):
        """Same plaintext/key yields different ciphertext via fresh IV."""
        key = b'SESSIONKEY123456'

        a = cbc_encrypt(b'halo bob', key)
        b = cbc_encrypt(b'halo bob', key)

        self.assertNotEqual(a[:16], b[:16])
        self.assertNotEqual(a, b)
        self.assertEqual(cbc_decrypt(a, key), b'halo bob')
        self.assertEqual(cbc_decrypt(b, key), b'halo bob')

    def test_hmac_rejects_changed_ciphertext(self):
        key = b'SESSIONKEY123456'
        packet = seal({'text': 'halo bob'}, key)

        original = packet['ciphertext']
        packet['ciphertext'] = (
            ('0' if original[0] != '0' else '1') + original[1:]
        )

        with self.assertRaisesRegex(ValueError, 'Authentication failed'):
            open_seal(packet, key)

    def test_hmac_rejects_wrong_key(self):
        packet = seal(
            {'text': 'halo bob'},
            b'SESSIONKEY123456'
        )

        with self.assertRaisesRegex(ValueError, 'Authentication failed'):
            open_seal(packet, b'OTHERSESSIONKEY!')

    def test_renew_repeats_handshake_with_new_ks(self):
        """Two consecutive five-step handshakes without restarting servers."""

        kdc = socket.socket()
        bob = socket.socket()

        kdc.bind(('127.0.0.1', 0))
        bob.bind(('127.0.0.1', 0))

        kdc.listen(2)
        bob.listen(2)

        kdc_port = kdc.getsockname()[1]
        bob_port = bob.getsockname()[1]

        errors = []
        seen = []

        def kdc_worker():
            try:
                for _ in range(2):
                    conn, addr = kdc.accept()
                    with conn:
                        kdc_handle(
                            conn, addr,
                            {'ka': KA, 'kb': KB}
                        )
            except Exception as exc:
                errors.append(exc)

        def bob_worker():
            try:
                for _ in range(2):
                    conn, _ = bob.accept()

                    with conn:
                        ks = bob_handshake(conn, KB)
                        seen.append(ks)
                        bob_listen(conn, ks)

            except Exception as exc:
                errors.append(exc)

        t1 = threading.Thread(
            target=kdc_worker,
            daemon=True
        )
        t2 = threading.Thread(
            target=bob_worker,
            daemon=True
        )

        t1.start()
        t2.start()

        try:
            for _ in range(2):
                conn, ks = alice_handshake(
                    '127.0.0.1', kdc_port,
                    '127.0.0.1', bob_port,
                    KA
                )

                with conn:
                    send(conn, {'type': 'renew'})

            t1.join(timeout=5)
            t2.join(timeout=5)

            self.assertFalse(
                t1.is_alive(),
                'KDC worker did not finish'
            )
            self.assertFalse(
                t2.is_alive(),
                'Bob worker did not finish'
            )
            self.assertFalse(errors, str(errors))
            self.assertEqual(len(seen), 2)
            self.assertNotEqual(seen[0], seen[1])

        finally:
            kdc.close()
            bob.close()


if __name__ == '__main__':
    unittest.main()