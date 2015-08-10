# Neutron Docker network driver
 
This repository implements OpenStack Neutron driver for the Docker networking
[remote driver](https://github.com/docker/libnetwork/blob/master/docs/remote.md).

Using the driver will result in the Docker containers joining one or more
existing or newly created Neutron networks. Each Neutron port type will have to
add support to this repository for plugging the ports it owns.

Currently, only `ovs` port is supported.

## How to run it

Deploy procedure:

* Deploy OpenStack
* Deploy neutron-openvswitch-agent on docker host if docker host and OpenStack host is not the same one
* Deploy this repository via `python setup.py install` on docker host

Starting neutron docker plugin:

```
mkdir -p /usr/lib/docker/plugins
neutron-docker --config-file /etc/docker/neutron_docker_plugin.conf --log-dir /var/log --debug
```

Now, you can create docker network with driver `neutron`:

```
docker network create -d neutron neutronnet
```

Run container using neutron network:

```
docker run -itd --publish-service=http1.neutronnet nginx
docker run -itd --publish-service=http2.neutronnet nginx
```

## How it works

Neutron L2 agent (such as neutron-openvswitch-agent) will be running on each
docker host. When a container is launched by the docker daemon using neutron
network plugin, for example:

```
docker run -itd --publish-service=http1.neutronnet nginx
```

Then docker will request its neutron driver to provide a `neutronnet` network
and `http1` endpoint. Actually, neutron driver will create a network whose name 
is `neutronet`'s network ID and a port whose name is `http1`'s endpoint ID. Neutron
driver will also setup essential virtual bridges and veth pairs which connects 
container's network interface to neutron L2 agent.
