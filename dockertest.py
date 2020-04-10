import os
import docker


#client = docker.DockerClient(base_url='tcp://127.0.0.1:2375')

#container = client.containers.run('gantapritham4/sdnnfv',cap_add=['NET_ADMIN','NET_RAW'],name='snort',detach=True,tty=True);

demo = "demo"

os.system('ovs-vsctl add-br ' + str(demo))
os.system('ifconfig demo up')
os.system('ovs-docker add-port demo eth1 snort')
os.system('ovs-docker add-port demo eth2 snort')
os.system('ip link add veth0 type veth peer name veth1')
os.system('ifconfig veth1 up')
os.system('ifconfig veth0 up')
os.system('ovs-vsctl add-port demo veth1')
os.system('ovs-vsctl add-port vswitch1 veth0')
os.system('ovs-ofctl add-flow demo in_port=3,actions=output:1')
os.system('ovs-ofctl add-flow demo in_port=2,actions=output:3')

os.system('ovs-ofctl mod-port demo 3 no-receive-stp')
os.system('ovs-ofctl mod-port demo 1 no-flood')
os.system('ovs-ofctl mod-port demo 2 no-flood')
os.system('ovs-ofctl mod-port demo 2 no-packet-in')

#result = container.exec_run('sh -c \'snort -A console -l /tmp -c /etc/snort/snort.conf -Q -i eth1:eth2\'',stderr=True,stdout=True)

#print("exit-code: " + str(result.exit_code))

#for line in result:
#        print(line)

#container.stop()
#print(container.status)
#container.remove()

#print container.logs()

