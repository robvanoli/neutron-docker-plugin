#!/bin/bash
# This is a demo openstack environment installed via packstack
sudo yum update -y
sudo yum install -y https://rdoproject.org/repos/rdo-release.rpm
sudo yum install -y openstack-packstack

# you can generate answer file and install only required keystone/neutron
# packstack --gen-answer-file=my_answer.txt
# packstack --answer-file=my_answer.txt
sudo packstack --allinone

