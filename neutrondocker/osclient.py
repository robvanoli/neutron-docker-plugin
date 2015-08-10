#!/usr/bin/env python
# Copyright 2015 feisky<feiskyer@gmail.com>
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

"""OpenStack client wrapping"""

import urlparse
from keystoneclient import discover as keystone_discover
from keystoneclient.v2_0 import client as keystone_v2
from keystoneclient.v3 import client as keystone_v3


def cached(func):
    """Cache client handles."""
    def wrapper(self, *args, **kwargs):
        key = '{0}{1}{2}'.format(func.__name__,
                                 str(args) if args else '',
                                 str(kwargs) if kwargs else '')

        if key in self.cache:
            return self.cache[key]
        self.cache[key] = func(self, *args, **kwargs)
        return self.cache[key]
    return wrapper


def create_keystone_client(args):
    discover = keystone_discover.Discover(**args)
    for version_data in discover.version_data():
        version = version_data['version']
        if version[0] <= 2:
            return keystone_v2.Client(**args)
        elif version[0] == 3:
            return keystone_v3.Client(**args)
    raise Exception(
        'Failed to discover keystone version for url %(auth_url)s.', **args)


class Endpoint(object):

    def __init__(self, auth_url, username, password, tenant_name=None,
                 permission="admin",
                 region_name=None, use_public_urls=False, admin_port=35357,
                 domain_name=None, user_domain_name='Default',
                 project_domain_name='Default'):
        self.auth_url = auth_url
        self.username = username
        self.password = password
        self.tenant_name = tenant_name
        self.permission = permission
        self.region_name = region_name
        self.use_public_urls = use_public_urls
        self.admin_port = admin_port
        self.domain_name = domain_name
        self.user_domain_name = user_domain_name
        self.project_domain_name = project_domain_name

    def to_dict(self, include_permission=False):
        dct = {"auth_url": self.auth_url, "username": self.username,
               "password": self.password, "tenant_name": self.tenant_name,
               "region_name": self.region_name,
               "use_public_urls": self.use_public_urls,
               "admin_port": self.admin_port,
               "domain_name": self.domain_name,
               "user_domain_name": self.user_domain_name,
               "project_domain_name": self.project_domain_name}
        if include_permission:
            dct["permission"] = self.permission
        return dct


class Clients(object):
    """This class simplify and unify work with openstack python clients."""
    def __init__(self, endpoint, conf):
        self.endpoint = endpoint
        self.cache = {}
        self.conf = conf

    def clients(self, client_type):
        return getattr(self, client_type)()

    @cached
    def keystone(self):
        """Return keystone client."""
        new_kw = {
            "timeout": self.conf.openstack_client_http_timeout,
            "insecure": self.conf.https_insecure, "cacert": self.conf.https_cacert
        }
        kw = dict(self.endpoint.to_dict().items() + new_kw.items())
        if kw["use_public_urls"]:
            mgmt_url = urlparse.urlparse(kw["auth_url"])
            if mgmt_url.port != kw["admin_port"]:
                kw["endpoint"] = "{0}://{1}:{2}{3}".format(
                    mgmt_url.scheme,
                    mgmt_url.hostname,
                    kw["admin_port"],
                    mgmt_url.path
                )
            else:
                kw["endpoint"] = kw["auth_url"]
        client = create_keystone_client(kw)
        client.authenticate()
        return client

    def verified_keystone(self):
        """Ensure keystone endpoints are valid and then authenticate
        :returns: Keystone Client
        """
        client = None
        try:
            # Ensure that user is admin
            client = self.keystone()
            if 'admin' not in [role.lower() for role in
                               client.auth_ref.role_names]:
                raise Exception(
                    'not valid endpoint %s' % self.endpoint.username)
        except Exception, e:
            raise e
        return client

    @cached
    def neutron(self, version='2.0'):
        """Return neutron client."""
        from neutronclient.neutron import client as neutron
        kc = self.keystone()
        network_api_url = kc.service_catalog.url_for(
            service_type='network', endpoint_type='public',
            region_name=self.endpoint.region_name)
        print network_api_url
        client = neutron.Client(version,
                                token=kc.auth_token,
                                endpoint_url=network_api_url,
                                timeout=self.conf.openstack_client_http_timeout,
                                insecure=self.conf.https_insecure,
                                ca_cert=self.conf.https_cacert)
        return client

