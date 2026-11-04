"""IP literals and regional Azure tenants are not registrable-domain siblings."""
import unittest

from origami.core.scope import reg_domain, same_host, same_site


class TestAddressScope(unittest.TestCase):
    def test_ipv4_addresses_with_same_suffix_are_different_sites(self):
        self.assertFalse(same_site('10.0.2.3', '192.168.2.3'))
        self.assertEqual(reg_domain('10.0.2.3:8443'), '10.0.2.3')

    def test_ipv6_is_compared_as_full_address(self):
        self.assertFalse(same_host('[2001:db8::1]:443', '[2001:db8::2]:443'))
        self.assertFalse(same_site('2001:db8::1', '2001:db8::2'))
        self.assertTrue(same_host('[2001:db8::1]:443', '2001:0db8:0:0:0:0:0:1'))
        self.assertEqual(reg_domain('[::1]:8080'), '::1')

    def test_dns_rules_still_work(self):
        self.assertTrue(same_site('cdn.example.com.br', 'app.example.com.br'))
        self.assertTrue(same_host('www.example.com:443', 'example.com'))
        self.assertFalse(same_site('a.github.io', 'b.github.io'))
        self.assertFalse(same_site('', ''))

    def test_regional_azure_hosts_are_separate_tenants(self):
        a = 'app-a.centralus-01.azurewebsites.net'
        b = 'app-b.centralus-01.azurewebsites.net'
        self.assertFalse(same_site(a, b))
        self.assertTrue(same_site(a, a.upper()))
        self.assertFalse(same_site('app-a.azurewebsites.net', 'app-b.azurewebsites.net'))
