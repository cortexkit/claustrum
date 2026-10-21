"""Run the independent HPKE receiver against the vault's pinned `credential.seal` reply.

`scripts/hpke-independent-open.py` opens that reply with a from-the-RFC Auth-mode
receiver built on the `cryptography` package, not on the Rust `hpke` crate the vault
seals with. It needs that package, so this test skips (and says so) where it is
missing rather than failing an environment that cannot run it.
"""
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'hpke-independent-open.py'
HAVE_CRYPTOGRAPHY = importlib.util.find_spec('cryptography') is not None


@unittest.skipUnless(HAVE_CRYPTOGRAPHY, 'the cryptography package is not installed')
class IndependentHpkeOpen(unittest.TestCase):
    def load(self):
        spec = importlib.util.spec_from_file_location('hpke_independent_open', SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_the_vault_seal_opens_and_every_one_bit_tamper_fails(self):
        result = subprocess.run([sys.executable, SCRIPT.as_posix()], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('opened all 257 published RFC 9180 mode-2 encryptions', result.stdout)
        self.assertIn('vault seal: opened 20 bytes under the vault key', result.stdout)
        self.assertEqual(result.stdout.count('tamper control:'), 3, result.stdout)

    def test_the_receiver_refuses_a_seal_from_another_sender(self):
        # The receiver must bind the sender's static key, or it would accept a push
        # sealed by anyone. Opening the real sample under a different sender's public
        # half has to fail.
        hpke = self.load()
        sample = hpke.seal_sample()
        other_sender = hpke.public_of(bytes(range(1, 33)))
        with self.assertRaises(hpke.InvalidTag):
            hpke.open_auth(sample['recipient_secret'], other_sender, sample['enc'],
                           sample['ciphertext'], sample['info'], sample['aad'])
        self.assertEqual(
            hpke.open_auth(sample['recipient_secret'], sample['sender_public'], sample['enc'],
                           sample['ciphertext'], sample['info'], sample['aad']),
            sample['plaintext'])


if __name__ == '__main__':
    unittest.main()
