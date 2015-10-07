**Create container using neutron network plugin**

```
docker network create --driver neutron net1

docker service publish bar.net1
docker service info bar.net1
CID=$(sudo docker run -itd centos)
docker service attach $CID bar.net1

#docker run --publish-service=bar.net1 -itd centos
```

**Stop container and clear services**

```
CID=$(docker ps | awk '/centos/{print $1}')
docker service detach $CID bar.net1
docker service unpublish bar.net1
docker network rm net1
docker rm -f $CID
```
