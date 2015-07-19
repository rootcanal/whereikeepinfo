import unittest
import base64
import tempfile
from Crypto.Cipher import AES

from whereikeepinfo.views import utils


class TestEncryption(unittest.TestCase):

    def setUp(self):
        self.message = 'test message'
        self.file = tempfile.NamedTemporaryFile()
        self.file.write(self.message)
        self.file.flush()
        self.file.seek(0)
        self.name = 'name'
        self.email = 'email'
        self.passphrase = 'passphrase'

    def tearDown(self):
        self.file.close()

    def test_padding_pads(self):
        padded = utils.pad(self.passphrase)
        self.assertTrue(len(self.passphrase) % 16 != 0)
        self.assertTrue(len(padded) % 16 == 0)

    def test_keygen_creates_valid_pub(self):
        pub, _ = utils.keygen(self.name, self.email, self.passphrase)
        pub = base64.b64decode(pub)
        self.assertTrue(pub.startswith('-----BEGIN PGP PUBLIC KEY BLOCK-----'))
        self.assertTrue(pub.endswith('-----END PGP PUBLIC KEY BLOCK-----\n'))

    def test_keygen_creates_valid_priv(self):
        _, priv = utils.keygen(self.name, self.email, self.passphrase)
        cipher = AES.new(utils.pad(self.passphrase))
        priv = base64.b64decode(priv)
        priv = cipher.decrypt(priv)
        priv = priv.rstrip('x')
        self.assertTrue(priv.startswith('-----BEGIN PGP PRIVATE KEY BLOCK-----'))
        self.assertTrue(priv.endswith('-----END PGP PRIVATE KEY BLOCK-----\n'))

    def test_encrypt_creates_valid_msg(self):
        pub, priv = utils.keygen(self.name, self.email, self.passphrase)
        encrypted = utils.encrypt(self.file, pub)
        self.assertTrue(encrypted.startswith('-----BEGIN PGP MESSAGE-----'))
        self.assertTrue(encrypted.endswith('-----END PGP MESSAGE-----\n'))

    def test_decrypt_creates_valid_msg(self):
        pub, priv = utils.keygen(self.name, self.email, self.passphrase)
        encrypted = utils.encrypt(self.file, pub)
        decrypted = utils.decrypt(encrypted, priv, pub, self.passphrase)
        self.assertEquals(decrypted, self.message)
