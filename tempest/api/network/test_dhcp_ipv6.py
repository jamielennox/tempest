# Copyright 2014 OpenStack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import netaddr
import random

from tempest.api.network import base
from tempest.common.utils import data_utils
from tempest import config
from tempest import exceptions

CONF = config.CONF


class NetworksTestDHCPv6(base.BaseNetworkTest):
    _ip_version = 6

    """ Test DHCPv6 specific features using SLAAC, stateless and
    stateful settings for subnets. Also it shall check dual-stack
    functionality (IPv4 + IPv6 together).
    The tests include:
        generating of SLAAC EUI-64 address in subnets with various settings
        receiving SLAAC addresses in combinations of various subnets
        receiving stateful IPv6 addresses
        addressing in subnets with router
    """

    @classmethod
    def skip_checks(cls):
        msg = None
        if not CONF.network_feature_enabled.ipv6:
            msg = "IPv6 is not enabled"
        elif not CONF.network_feature_enabled.ipv6_subnet_attributes:
            msg = "DHCPv6 attributes are not enabled."
        if msg:
            raise cls.skipException(msg)

    @classmethod
    def resource_setup(cls):
        super(NetworksTestDHCPv6, cls).resource_setup()
        cls.network = cls.create_network()

    def _remove_from_list_by_index(self, things_list, elem):
        for index, i in enumerate(things_list):
            if i['id'] == elem['id']:
                break
        del things_list[index]

    def _clean_network(self):
        body = self.client.list_ports()
        ports = body['ports']
        for port in ports:
            if (port['device_owner'].startswith('network:router_interface')
                and port['device_id'] in [r['id'] for r in self.routers]):
                self.client.remove_router_interface_with_port_id(
                    port['device_id'], port['id']
                )
            else:
                if port['id'] in [p['id'] for p in self.ports]:
                    self.client.delete_port(port['id'])
                    self._remove_from_list_by_index(self.ports, port)
        body = self.client.list_subnets()
        subnets = body['subnets']
        for subnet in subnets:
            if subnet['id'] in [s['id'] for s in self.subnets]:
                self.client.delete_subnet(subnet['id'])
                self._remove_from_list_by_index(self.subnets, subnet)
        body = self.client.list_routers()
        routers = body['routers']
        for router in routers:
            if router['id'] in [r['id'] for r in self.routers]:
                self.client.delete_router(router['id'])
                self._remove_from_list_by_index(self.routers, router)

    def _get_ips_from_subnet(self, **kwargs):
        subnet = self.create_subnet(self.network, **kwargs)
        port_mac = data_utils.rand_mac_address()
        port = self.create_port(self.network, mac_address=port_mac)
        real_ip = next(iter(port['fixed_ips']), None)['ip_address']
        eui_ip = data_utils.get_ipv6_addr_by_EUI64(subnet['cidr'],
                                                   port_mac).format()
        return real_ip, eui_ip

    def test_dhcpv6_stateless_eui64(self):
        """When subnets configured with RAs SLAAC (AOM=100) and DHCP stateless
        (AOM=110) both for radvd and dnsmasq, port shall receive IP address
        calculated from its MAC.
        """
        for ra_mode, add_mode in (
                ('slaac', 'slaac'),
                ('dhcpv6-stateless', 'dhcpv6-stateless'),
        ):
            kwargs = {'ipv6_ra_mode': ra_mode,
                      'ipv6_address_mode': add_mode}
            real_ip, eui_ip = self._get_ips_from_subnet(**kwargs)
            self._clean_network()
            self.assertEqual(eui_ip, real_ip,
                             ('Real port IP is %s, but shall be %s when '
                              'ipv6_ra_mode=%s and ipv6_address_mode=%s') % (
                                 real_ip, eui_ip, ra_mode, add_mode))

    def test_dhcpv6_stateless_no_ra(self):
        """When subnets configured with dnsmasq SLAAC and DHCP stateless
        and there is no radvd, port shall receive IP address calculated
        from its MAC and mask of subnet.
        """
        for ra_mode, add_mode in (
                (None, 'slaac'),
                (None, 'dhcpv6-stateless'),
        ):
            kwargs = {'ipv6_ra_mode': ra_mode,
                      'ipv6_address_mode': add_mode}
            kwargs = {k: v for k, v in kwargs.iteritems() if v}
            real_ip, eui_ip = self._get_ips_from_subnet(**kwargs)
            self._clean_network()
            self.assertEqual(eui_ip, real_ip,
                             ('Real port IP %s shall be equal to EUI-64 %s'
                              'when ipv6_ra_mode=%s,ipv6_address_mode=%s') % (
                                 real_ip, eui_ip,
                                 ra_mode if ra_mode else "Off",
                                 add_mode if add_mode else "Off"))

    def test_dhcpv6_invalid_options(self):
        """Different configurations for radvd and dnsmasq are not allowed"""
        for ra_mode, add_mode in (
                ('dhcpv6-stateless', 'dhcpv6-stateful'),
                ('dhcpv6-stateless', 'slaac'),
                ('slaac', 'dhcpv6-stateful'),
                ('dhcpv6-stateful', 'dhcpv6-stateless'),
                ('dhcpv6-stateful', 'slaac'),
                ('slaac', 'dhcpv6-stateless'),
        ):
            kwargs = {'ipv6_ra_mode': ra_mode,
                      'ipv6_address_mode': add_mode}
            self.assertRaises(exceptions.BadRequest,
                              self.create_subnet,
                              self.network,
                              **kwargs)

    def test_dhcpv6_stateless_no_ra_no_dhcp(self):
        """If no radvd option and no dnsmasq option is configured
        port shall receive IP from fixed IPs list of subnet.
        """
        real_ip, eui_ip = self._get_ips_from_subnet()
        self._clean_network()
        self.assertNotEqual(eui_ip, real_ip,
                            ('Real port IP %s equal to EUI-64 %s when '
                             'ipv6_ra_mode=Off and ipv6_address_mode=Off,'
                             'but shall be taken from fixed IPs') % (
                                real_ip, eui_ip))

    def test_dhcpv6_two_subnets(self):
        """When one IPv6 subnet configured with dnsmasq SLAAC or DHCP stateless
        and other IPv6 is with DHCP stateful, port shall receive EUI-64 IP
        addresses from first subnet and DHCP address from second one.
        Order of subnet creating should be unimportant.
        """
        for order in ("slaac_first", "dhcp_first"):
            for ra_mode, add_mode in (
                    ('slaac', 'slaac'),
                    ('dhcpv6-stateless', 'dhcpv6-stateless'),
            ):
                kwargs = {'ipv6_ra_mode': ra_mode,
                          'ipv6_address_mode': add_mode}
                kwargs_dhcp = {'ipv6_address_mode': 'dhcpv6-stateful'}
                if order == "slaac_first":
                    subnet_slaac = self.create_subnet(self.network, **kwargs)
                    subnet_dhcp = self.create_subnet(
                        self.network, **kwargs_dhcp)
                else:
                    subnet_dhcp = self.create_subnet(
                        self.network, **kwargs_dhcp)
                    subnet_slaac = self.create_subnet(self.network, **kwargs)
                port_mac = data_utils.rand_mac_address()
                dhcp_ip = subnet_dhcp["allocation_pools"][0]["start"]
                eui_ip = data_utils.get_ipv6_addr_by_EUI64(
                    subnet_slaac['cidr'],
                    port_mac
                ).format()
                # TODO(sergsh): remove this when 1219795 is fixed
                dhcp_ip = [dhcp_ip, (netaddr.IPAddress(dhcp_ip) + 1).format()]
                port = self.create_port(self.network, mac_address=port_mac)
                real_ips = dict([(k['subnet_id'], k['ip_address'])
                                 for k in port['fixed_ips']])
                real_dhcp_ip, real_eui_ip = [real_ips[sub['id']]
                                             for sub in subnet_dhcp,
                                             subnet_slaac]
                self.client.delete_port(port['id'])
                self.ports.pop()
                body = self.client.list_ports()
                ports_id_list = [i['id'] for i in body['ports']]
                self.assertNotIn(port['id'], ports_id_list)
                self._clean_network()
                self.assertEqual(real_eui_ip,
                                 eui_ip,
                                 'Real IP is {0}, but shall be {1}'.format(
                                     real_eui_ip,
                                     eui_ip))
                self.assertIn(
                    real_dhcp_ip, dhcp_ip,
                    'Real IP is {0}, but shall be one from {1}'.format(
                        real_dhcp_ip,
                        str(dhcp_ip)))

    def test_dhcpv6_64_subnets(self):
        """When one IPv6 subnet configured with dnsmasq SLAAC or DHCP stateless
        and other IPv4 is with DHCP of IPv4, port shall receive EUI-64 IP
        addresses from first subnet and IPv4 DHCP address from second one.
        Order of subnet creating should be unimportant.
        """
        for order in ("slaac_first", "dhcp_first"):
            for ra_mode, add_mode in (
                    ('slaac', 'slaac'),
                    ('dhcpv6-stateless', 'dhcpv6-stateless'),
            ):
                kwargs = {'ipv6_ra_mode': ra_mode,
                          'ipv6_address_mode': add_mode}
                if order == "slaac_first":
                    subnet_slaac = self.create_subnet(self.network, **kwargs)
                    subnet_dhcp = self.create_subnet(
                        self.network, ip_version=4)
                else:
                    subnet_dhcp = self.create_subnet(
                        self.network, ip_version=4)
                    subnet_slaac = self.create_subnet(self.network, **kwargs)
                port_mac = data_utils.rand_mac_address()
                dhcp_ip = subnet_dhcp["allocation_pools"][0]["start"]
                eui_ip = data_utils.get_ipv6_addr_by_EUI64(
                    subnet_slaac['cidr'],
                    port_mac
                ).format()
                # TODO(sergsh): remove this when 1219795 is fixed
                dhcp_ip = [dhcp_ip, (netaddr.IPAddress(dhcp_ip) + 1).format()]
                port = self.create_port(self.network, mac_address=port_mac)
                real_ips = dict([(k['subnet_id'], k['ip_address'])
                                 for k in port['fixed_ips']])
                real_dhcp_ip, real_eui_ip = [real_ips[sub['id']]
                                             for sub in subnet_dhcp,
                                             subnet_slaac]
                self._clean_network()
                self.assertTrue({real_eui_ip,
                                 real_dhcp_ip}.issubset([eui_ip] + dhcp_ip))
                self.assertEqual(real_eui_ip,
                                 eui_ip,
                                 'Real IP is {0}, but shall be {1}'.format(
                                     real_eui_ip,
                                     eui_ip))
                self.assertIn(
                    real_dhcp_ip, dhcp_ip,
                    'Real IP is {0}, but shall be one from {1}'.format(
                        real_dhcp_ip,
                        str(dhcp_ip)))

    def test_dhcp_stateful(self):
        """With all options below, DHCPv6 shall allocate first
        address from subnet pool to port.
        """
        for ra_mode, add_mode in (
                ('dhcpv6-stateful', 'dhcpv6-stateful'),
                ('dhcpv6-stateful', None),
                (None, 'dhcpv6-stateful'),
        ):
            kwargs = {'ipv6_ra_mode': ra_mode,
                      'ipv6_address_mode': add_mode}
            kwargs = {k: v for k, v in kwargs.iteritems() if v}
            subnet = self.create_subnet(self.network, **kwargs)
            port = self.create_port(self.network)
            port_ip = next(iter(port['fixed_ips']), None)['ip_address']
            dhcp_ip = subnet["allocation_pools"][0]["start"]
            # TODO(sergsh): remove this when 1219795 is fixed
            dhcp_ip = [dhcp_ip, (netaddr.IPAddress(dhcp_ip) + 1).format()]
            self._clean_network()
            self.assertIn(
                port_ip, dhcp_ip,
                'Real IP is {0}, but shall be one from {1}'.format(
                    port_ip,
                    str(dhcp_ip)))

    def test_dhcp_stateful_fixedips(self):
        """With all options below, port shall be able to get
        requested IP from fixed IP range not depending on
        DHCP stateful (not SLAAC!) settings configured.
        """
        for ra_mode, add_mode in (
                ('dhcpv6-stateful', 'dhcpv6-stateful'),
                ('dhcpv6-stateful', None),
                (None, 'dhcpv6-stateful'),
        ):
            kwargs = {'ipv6_ra_mode': ra_mode,
                      'ipv6_address_mode': add_mode}
            kwargs = {k: v for k, v in kwargs.iteritems() if v}
            subnet = self.create_subnet(self.network, **kwargs)
            ip_range = netaddr.IPRange(subnet["allocation_pools"][0]["start"],
                                       subnet["allocation_pools"][0]["end"])
            ip = netaddr.IPAddress(random.randrange(ip_range.first,
                                                    ip_range.last)).format()
            port = self.create_port(self.network,
                                    fixed_ips=[{'subnet_id': subnet['id'],
                                                'ip_address': ip}])
            port_ip = next(iter(port['fixed_ips']), None)['ip_address']
            self._clean_network()
            self.assertEqual(port_ip, ip,
                             ("Port IP %s is not as fixed IP from "
                              "port create request: %s") % (
                                 port_ip, ip))

    def test_dhcp_stateful_fixedips_outrange(self):
        """When port gets IP address from fixed IP range it
        shall be checked if it's from subnets range.
        """
        kwargs = {'ipv6_ra_mode': 'dhcpv6-stateful',
                  'ipv6_address_mode': 'dhcpv6-stateful'}
        subnet = self.create_subnet(self.network, **kwargs)
        ip_range = netaddr.IPRange(subnet["allocation_pools"][0]["start"],
                                   subnet["allocation_pools"][0]["end"])
        ip = netaddr.IPAddress(random.randrange(
            ip_range.last + 1, ip_range.last + 10)).format()
        self.assertRaises(exceptions.BadRequest,
                          self.create_port,
                          self.network,
                          fixed_ips=[{'subnet_id': subnet['id'],
                                      'ip_address': ip}])

    def test_dhcp_stateful_fixedips_duplicate(self):
        """When port gets IP address from fixed IP range it
        shall be checked if it's not duplicate.
        """
        kwargs = {'ipv6_ra_mode': 'dhcpv6-stateful',
                  'ipv6_address_mode': 'dhcpv6-stateful'}
        subnet = self.create_subnet(self.network, **kwargs)
        ip_range = netaddr.IPRange(subnet["allocation_pools"][0]["start"],
                                   subnet["allocation_pools"][0]["end"])
        ip = netaddr.IPAddress(random.randrange(
            ip_range.first, ip_range.last)).format()
        self.create_port(self.network,
                         fixed_ips=[
                             {'subnet_id': subnet['id'],
                              'ip_address': ip}])
        self.assertRaisesRegexp(exceptions.Conflict,
                                "object with that identifier already exists",
                                self.create_port,
                                self.network,
                                fixed_ips=[{'subnet_id': subnet['id'],
                                            'ip_address': ip}])

    def _create_subnet_router(self, kwargs):
        subnet = self.create_subnet(self.network, **kwargs)
        router = self.create_router(
            router_name=data_utils.rand_name("routerv6-"),
            admin_state_up=True)
        port = self.create_router_interface(router['id'],
                                            subnet['id'])
        body = self.client.show_port(port['port_id'])
        return subnet, body['port']

    def test_dhcp_stateful_router(self):
        """With all options below the router interface shall
        receive DHCPv6 IP address from allocation pool.
        """
        for ra_mode, add_mode in (
                ('dhcpv6-stateful', 'dhcpv6-stateful'),
                ('dhcpv6-stateful', None),
        ):
            kwargs = {'ipv6_ra_mode': ra_mode,
                      'ipv6_address_mode': add_mode}
            kwargs = {k: v for k, v in kwargs.iteritems() if v}
            subnet, port = self._create_subnet_router(kwargs)
            port_ip = next(iter(port['fixed_ips']), None)['ip_address']
            self._clean_network()
            self.assertEqual(port_ip, subnet['gateway_ip'],
                             ("Port IP %s is not as first IP from "
                              "subnets allocation pool: %s") % (
                                 port_ip, subnet['gateway_ip']))

    def tearDown(self):
        self._clean_network()
        super(NetworksTestDHCPv6, self).tearDown()
