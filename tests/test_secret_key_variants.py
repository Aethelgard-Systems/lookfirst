import unittest

from lookfirst.schleuse import Schleuse


class SecretKeyVariants(unittest.TestCase):
    def test_named_secrets_in_structured_and_free_text(self):
        for name in ('db_password', 'DB-PASSWORD', 'dbpassword', 'access_token',
                     'ACCESS-TOKEN', 'accesstoken'):
            with self.subTest(name=name):
                gate = Schleuse()
                value = 'synthetic-secret-value'
                self.assertNotIn(value, gate.mask({name: value})[name])
                self.assertNotIn(value, gate.mask_text(f'{name}="{value}"'))

    def test_unrelated_keys_stay_unchanged(self):
        gate = Schleuse()
        self.assertEqual(gate.mask({'access_count': 'ordinary-value',
                                    'db_username': 'ordinary-value'}),
                         {'access_count': 'ordinary-value', 'db_username': 'ordinary-value'})
