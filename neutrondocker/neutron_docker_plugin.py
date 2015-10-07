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

"""Using neutron as docker network plugin"""

import atexit
import json
import netaddr
import os
import random
import shlex
import sys

from flask import abort, Flask, jsonify, request
from oslo_config import cfg
from oslo_concurrency import processutils
from oslo_log import log
from neutrondocker import osclient

CIDR_RETRY_TIMES = 10
MODEL_NAME = "neutrondocker"
PLUGIN_DIR = "/usr/lib/docker/plugins"
PLUGIN_FILE = "/usr/lib/docker/plugins/neutron.spec"

openstack_opts = [
    cfg.StrOpt("os_username", default="",
               help="openstack username"),
    cfg.StrOpt("os_tenant_name", default="",
               help="openstack user tenant name"),
    cfg.StrOpt("os_user_password", default="",
               help="openstack user password"),
    cfg.StrOpt("os_auth_url", default="",
               help="openstack keystone auth url"),
    cfg.StrOpt("integration_bridge", default="br-int",
               help="openstack integration bridge name"),
    cfg.FloatOpt("openstack_client_http_timeout", default=180.0),
    cfg.BoolOpt("https_insecure", default=False),
    cfg.StrOpt("https_cacert", default=None)
]


CONF = cfg.CONF
CONF.register_opts(openstack_opts)
log.register_options(CONF)
CONF(project=MODEL_NAME)
log.setup(CONF, 'neutrondocker')
LOG = log.getLogger(__name__)
app = Flask(MODEL_NAME)
os_endpoint = osclient.Endpoint(CONF.os_auth_url,
                                CONF.os_username,
                                CONF.os_user_password,
                                CONF.os_tenant_name)
os_client = osclient.Clients(os_endpoint, CONF)
subnet_cache = []

def cleanup():
    if os.path.isfile(PLUGIN_FILE):
        os.remove(PLUGIN_FILE)


@app.route('/Plugin.Activate', methods=['POST'])
def plugin_activate():
    LOG.debug("/Plugin.Activate requested")
    return jsonify({"Implements": ["NetworkDriver"]})


def generate_subnet_cidr():
    if not len(subnet_cache):
        subnets = os_client.neutron().list_subnets()["subnets"]
        for subnet in subnets:
            subnet_cache.append(subnet['cidr'])

    for i in range(CIDR_RETRY_TIMES):
        # cidr = str(netaddr.IPNetwork(cidr).next())
        cidr = "10.%d.%d.0/20" % (random.randint(0, 254),
                                  random.randint(0, 254))
        if cidr not in subnet_cache:
            subnet_cache.append(cidr)
            return cidr

    return ""


def run_cmd(cmd, **kwargs):
    """Convenience wrapper around oslo's execute() method."""
    cmd_args = shlex.split(cmd)
    if 'run_as_root' in kwargs and 'root_helper' not in kwargs:
        kwargs['root_helper'] = "sudo"
    return processutils.execute(*cmd_args, **kwargs)[0]



@app.route('/NetworkDriver.CreateNetwork', methods=['POST'])
def create_network():
    json_data = request.get_json(force=True)
    LOG.debug("/NetworkDriver.CreateNetwork requested with %s", json_data)

    nid = json_data["NetworkID"]
    if not nid:
        error = "No NetworkID defined"
        LOG.error(error)
        return jsonify({'Err': error})

    try:
        networks = os_client.neutron().list_networks(name=nid)
    except Exception as e:
        error = "Querying network info failed: %s" % e
        LOG.error(error)
        return jsonify({'Err': error})

    if len(networks["networks"]) > 0:
        LOG.info("network %s already created, using existing", nid)
        return jsonify({})

    try:
        kw = {"name": nid}
        network = os_client.neutron().create_network({"network": kw})
    except Exception as e:
        LOG.error("Failed to create network %s: %s", nid, e)
        return jsonify({'Err': "Failed to create network"})

    network_id = network["network"]["id"]
    cidr = generate_subnet_cidr()
    try:
        subnet_kw = {
            "name": "sub" + nid,
            "network_id": network_id,
            "ip_version": 4,
            "cidr": cidr
        }
        os_client.neutron().create_subnet({"subnets": [subnet_kw]})
    except Exception as e:
        LOG.error("Failed to create subnet %s: %s", cidr, e)
        os_client.neutron().delete_network(network_id)
        return jsonify({'Err': "Failed to create network"})

    return jsonify({})


@app.route('/NetworkDriver.DeleteNetwork', methods=['POST'])
def delete_network():
    json_data = request.get_json(force=True)
    LOG.debug("/NetworkDriver.DeleteNetwork requested with %s", json_data)

    nid = json_data["NetworkID"]
    if not nid:
        error = "No NetworkID defined"
        LOG.error(error)
        return jsonify({'Err': error})

    try:
        networks = os_client.neutron().list_networks(name=nid)
    except Exception as e:
        error = "Querying network info failed: %s" % e
        LOG.error(error)
        return jsonify({'Err': error})

    try:
        for network in networks["networks"]:
            for subnet in network['subnets']:
                os_client.neutron().delete_subnet(subnet)
            os_client.neutron().delete_network(network['id'])
    except Exception as e:
        error = "Delete network failed: %s" % e
        LOG.error(error)
        return jsonify({'Err': error})

    return jsonify({})

@app.route('/NetworkDriver.CreateEndpoint', methods=['POST'])
def create_endpoint():
    json_data = request.get_json(force=True)
    LOG.debug("/NetworkDriver.CreateEndpoint requested with %s", json_data)

    nid = json_data["NetworkID"]
    if not nid:
        error = "No NetworkID defined"
        LOG.error(error)
        return jsonify({'Err': error})

    eid = json_data["EndpointID"]
    if not eid:
        error = "No EndpointID defined"
        LOG.error(error)
        return jsonify({'Err': error})

    try:
        networks = os_client.neutron().list_networks(name=nid)
    except Exception as e:
        error = "Querying network info failed: %s" % e
        LOG.error(error)
        return jsonify({'Err': error})

    if len(networks["networks"]) != 1:
        error = "Can not find network %s" % nid
        LOG.error(error)
        return jsonify({'Err': error})

    network = networks["networks"][0]
    port_kw = {
        'network_id': network['id'],
        'binding:profile': {"endpoint_id": eid},
        'name': eid + "_0",
        'admin_state_up': True}

    interfaces = json_data.get("Interfaces", [])
    ports = []
    if interfaces:
        for interface in interfaces:
            port_kw.update({'name': eid + "_" + interface["ID"]})
            try:
                os_client.neutron().create_port({'port': port_kw})
            except Exception as e:
                error = "Failed to create port %s: %s" % (port_kw, e)
                LOG.error(error)
                return jsonify({'Err': error})
    else:
        try:
            port = os_client.neutron().create_port({'port': port_kw})['port']
            LOG.debug("Port created: %s", port)
        except Exception as e:
            error = "Failed to create port %s: %s" % (port_kw, e)
            LOG.error(error)
            return jsonify({'Err': error})

        try:
            subnets = os_client.neutron().list_subnets({
                'subnet_id': port['fixed_ips'][0]['subnet_id']})['subnets']
            LOG.debug('Got subnet info %s', subnets)
        except Exception as e:
            error = "Failed to get subnet info for port %s" % port['id']
            LOG.exception(error)
            return jsonify({'Err': error})

        prefixlen = netaddr.IPNetwork(subnets[0]['cidr']).prefixlen
        ports.append({
            "ID": 0,
            "Address": "%s/%s" % (port['fixed_ips'][0]['ip_address'], prefixlen),
            "AddressIPv6": None,
            "MacAddress": port['mac_address']
        })

    return jsonify({"Interfaces": ports})


@app.route('/NetworkDriver.EndpointOperInfo', methods=['POST'])
def show_endpoint():
    json_data = request.get_json(force=True)
    LOG.debug("/NetworkDriver.EndpointOperInfo requested with %s", json_data)

    nid = json_data.get("NetworkID", "")
    if not nid:
        error = "No NetworkID defined"
        LOG.error(error)
        return jsonify({'Err': error})

    eid = json_data.get("EndpointID", "")
    if not eid:
        error = "No EndpointID defined"
        LOG.error(error)
        return jsonify({'Err': error})

    try:
        networks = os_client.neutron().list_networks(name=nid)
    except Exception as e:
        error = "Querying network info failed: %s" % e
        LOG.error(error)
        return jsonify({'Err': error})

    if len(networks["networks"]) != 1:
        error = "Can not find network %s" % nid
        LOG.error(error)
        return jsonify({'Err': error})

    network = networks["networks"][0]
    port_kw = {
        "network_id": network['id'],
        "name": eid + "_0",
        'binding:profile': {"endpoint_id": eid},
    }

    try:
        ports = os_client.neutron().list_ports(**port_kw)["ports"]
    except Exception as e:
        error = "Failed to get endpoint information %s" % eid
        return jsonify({'Err': error})

    interfaces = []
    for port in ports:
        mac_address = port['mac_address']
        ip_address = port['fixed_ips'][0]['ip_address']
        interfaces.append({'Address': ip_address, "MacAddress": mac_address})

    return jsonify({"Value": {"Interfaces": interfaces}})


@app.route('/NetworkDriver.DeleteEndpoint', methods=['POST'])
def delete_endpoint():
    json_data = request.get_json(force=True)
    LOG.debug("/NetworkDriver.EndpointOperInfo requested with %s", json_data)

    nid = json_data.get("NetworkID", "")
    if not nid:
        error = "No NetworkID defined"
        LOG.error(error)
        return jsonify({'Err': error})

    eid = json_data.get("EndpointID", "")
    if not eid:
        error = "No EndpointID defined"
        LOG.error(error)
        return jsonify({'Err': error})

    try:
        networks = os_client.neutron().list_networks(name=nid)
    except Exception as e:
        error = "Querying network info failed: %s" % e
        LOG.error(error)
        return jsonify({'Err': error})

    if len(networks["networks"]) != 1:
        error = "can not find network %s" % nid
        LOG.error(error)
        return jsonify({'Err': error})

    network = networks["networks"][0]
    port_kw = {
        "network_id": network['id'],
        "name": eid + "_0", 
        'binding:profile': {"endpoint_id": eid},
    }

    try:
        ports = os_client.neutron().list_ports(**port_kw)["ports"]
    except Exception as e:
        error = "Failed to get endpoint information %s: %s" % (eid, e)
        return jsonify({'Err': error})

    try:
        for port in ports:
            os_client.neutron.delete_port(port['id'])
    except Exception as e:
        error = "Failed to delete endpoint: %s" % e
        return jsonify({'Err': error})

    return jsonify({})

def get_br_name(port_id):
    return ('qbr' + port_id)[:14]

def get_tap_name(port_id):
    return (('tap' + port_id)[:14], ('vif' + port_id)[:14])

def setup_container_port(eid, vm_id, port):
    mac_address = port['mac_address']
    ip_address = port['fixed_ips'][0]['ip_address']
    if not mac_address or not ip_address:
        error = 'mac or ip_address null'
        raise Exception(error)

    qvb, qvo = get_veth_name(eid, port['id'])
    cmd = "ip link add %s type veth peer name %s" % (qvb, qvo)
    try:
        run_cmd(cmd)
    except Exception as e:
        error = "Failed to create veth pair for %s, exception: %s" % (vm_id, e)
        raise Exception(error)

    brname = get_br_name(port['id'])
    cmd = 'brctl addbr %s' % brname
    try:
        run_cmd(cmd)
    except Exception as e:
        error = "Running %s failed, exception: %s" % (cmd, e)
        raise Exception(error)

    cmd = 'brctl addif %s %s' % (brname, qvb)
    try:
        run_cmd(cmd)
    except Exception as e:
        error = "Running %s failed, exception: %s" % (cmd, e)
        raise Exception(error)

    tapname, vifname = get_tap_name(port['id'])
    cmd = "ip link add %s type veth peer name %s" % (tapname, vifname)
    try:
        run_cmd(cmd)
    except Exception as e:
        error = "Running %s failed, exception: %s" % (cmd, e)
        raise Exception(error)

    cmd = 'brctl addif %s %s' % (brname, tapname)
    try:
        run_cmd(cmd)
    except Exception as e:
        error = "Running %s failed, exception: %s" % (cmd, e)
        raise Exception(error)

    cmd = "ip link set dev %s address %s" % (vifname, mac_address)
    try:
        run_cmd(cmd)
    except Exception as e:
        error = "Running %s failed, exception: %s" % (cmd, e)
        raise Exception(error)

    cmd = "ip link set %s up" % (vifname)
    try:
        run_cmd(cmd)
    except Exception as e:
        error = "Running %s failed, exception: %s" % (cmd, e)
        raise Exception(error)

    cmd = "ip link set %s up" % (tapname)
    try:
        run_cmd(cmd)
    except Exception as e:
        error = "Running %s failed, exception: %s" % (cmd, e)
        raise Exception(error)

    cmd = "ovs-vsctl -vconsole:off -- --if-exists del-port %s " \
          "-- add-port %s %s " \
          "-- set interface %s " \
          "external_ids:attached-mac=%s " \
          "external_ids:iface-id=%s " \
          "external_ids:vm-id=%s " \
          "external_ids:iface-status=active" \
          % (qvo, CONF.integration_bridge, qvo, qvo,
             mac_address, port['id'], vm_id)
    try:
        run_cmd(cmd)
    except Exception as e:
        error = "Failed to setup address for %s, exception: %s" % (vm_id, e)
        raise Exception(error)


@app.route('/NetworkDriver.Join', methods=['POST'])
def network_join():
    data = json.loads(request.data)
    LOG.debug("/NetworkDriver.Join requested with %s", data)

    nid = data.get("NetworkID", "")
    if not nid:
        error = "No NetworkID defined"
        LOG.error(error)
        return jsonify({'Err': error})

    eid = data.get("EndpointID", "")
    if not eid:
        error = "No EndpointID defined"
        LOG.error(error)
        return jsonify({'Err': error})

    sboxkey = data.get("SandboxKey", "")
    if not sboxkey:
        error = "No SandboxKey defined"
        LOG.error(error)
        return jsonify({'Err': error})

    # sboxkey is of the form: /var/run/docker/netns/CONTAINER_ID
    LOG.debug("Join with sboxkey %s", sboxkey)
    vm_id = sboxkey.rsplit('/')[-1]

    try:
        networks = os_client.neutron().list_networks(name=nid)
    except Exception as e:
        error = "Querying network info failed: %s" % e
        LOG.error(error)
        return jsonify({'Err': error})

    if len(networks["networks"]) != 1:
        error = "Can not find network %s" % nid
        LOG.error(error)
        return jsonify({'Err': error})

    network = networks["networks"][0]
    port_kw = {
        "network_id": network['id'],
        "name": eid + "_0",
        'binding:profile': {"endpoint_id": eid},
    }

    try:
        ports = os_client.neutron().list_ports(**port_kw)["ports"]
    except Exception as e:
        error = "Failed to get endpoint information %s" % eid
        return jsonify({'Err': error})

    interfaces = []
    for port in ports:
        try:
            setup_container_port(eid, vm_id, port)
            interfaces.append({'SrcName': get_tap_name(port['id'])[1], "DstPrefix": "eth"})
        except Exception as e:
            error = "Failed to create a port (%s)" % (str(e))
            os_client.neutron().delete_port(port['id'])
            destroy_container_port(eid, port)
            return jsonify({'Err': error})

    result = {"InterfaceNames": interfaces,
              "Gateway": "",
              "GatewayIPv6": "",
              "HostsPath": "",
              "ResolvConfPath": ""}
    LOG.debug("Network join result %s", result)
    return jsonify(result)


def get_veth_name(eid, port_id):
    return ("qvb" + eid[:3] + port_id[:8], "qvo" + eid[:3] + port_id[:8])


def destroy_container_port(eid, port):
    qvb, qvo = get_veth_name(eid, port['id'])

    cmd = "ip link delete %s" % qvo
    try:
        run_cmd(cmd)
    except Exception as e:
        error = "Failed to delete qvb for %s, exception: %s" % (eid, e)
        LOG.warning(error)

    cmd = "ip link del %s" % get_tap_name(port['id'])[0]
    try:
        run_cmd(cmd)
    except Exception as e:
        error = "Failed to execute cmd %s, exception: %s" % (cmd, e)
        LOG.warning(error)

    cmd = "ovs-vsctl -vconsole:off --if-exists del-port %s" % qvo
    try:
        run_cmd(cmd)
    except Exception as e:
        error = "Failed to delete qvo for %s, exception: %s" % (eid, e)
        LOG.warning(error)

    brname = get_br_name(port['id'])
    cmd = "ip link set %s down" % (brname)
    try:
        run_cmd(cmd)
    except Exception as e:
        error = "Failed to execute cmd %s, exception: %s" % (cmd, e)
        LOG.warning(error)

    cmd = "brctl delbr %s" % (brname)
    try:
        run_cmd(cmd)
    except Exception as e:
        error = "Failed to execute cmd %s, exception: %s" % (cmd, e)
        LOG.warning(error)


@app.route('/NetworkDriver.Leave', methods=['POST'])
def network_leave():
    data = json.loads(request.data)
    LOG.debug("/NetworkDriver.Leave requested with %s", data)

    nid = data.get("NetworkID", "")
    if not nid:
        error = "No NetworkID defined"
        LOG.error(error)
        return jsonify({'Err': error})

    eid = data.get("EndpointID", "")
    if not eid:
        error = "No EndpointID defined"
        LOG.error(error)
        return jsonify({'Err': error})

    try:
        networks = os_client.neutron().list_networks(name=nid)
    except Exception as e:
        error = "Querying network info failed: %s" % e
        LOG.error(error)
        return jsonify({'Err': error})

    if len(networks["networks"]) != 1:
        error = "Can not find network %s" % nid
        LOG.error(error)
        return jsonify({'Err': error})

    network = networks["networks"][0]
    port_kw = {
        "network_id": network['id'],
        "name": eid + "_0",
        'binding:profile': {"endpoint_id": eid},
    }

    try:
        ports = os_client.neutron().list_ports(**port_kw)["ports"]
    except Exception as e:
        error = "Failed to get endpoint information %s" % eid
        return jsonify({'Err': error})

    for port in ports:
        try:
            destroy_container_port(eid, port)
        except Exception as e:
            error = "Failed to delete a port (%s)" % (str(e))
            return jsonify({'Err': error})

    return jsonify({})


def main():
    LOG.info("started")
    try:
        f = open(PLUGIN_FILE, "w")
        f.write("tcp://0.0.0.0:5057")
        f.close()
    except Exception as e:
        LOG.error('Can not write neutron.spec: %s', e)
    atexit.register(cleanup)
    if not os.path.isdir(PLUGIN_DIR):
        sys.exit("No docker plugin directory configured")
    app.debug = True
    app.run(host='0.0.0.0', port=5057)


if __name__ == '__main__':
    main()
