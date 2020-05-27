import os
'''
loop_num = int(os.popen("ovs-vsctl show | grep Bridge | awk '{print $2}' | wc -l").read())
print(loop_num)
while loop_num > 0:
    switch_name = os.popen("ovs-vsctl show | grep Bridge | awk '{print $2}' | sed -n '1p' ").read()
    #print(switch_name)
    comm = "ovs-vsctl del-br " + switch_name
    print(comm)
    os.system(comm)
    loop_num-=1

os.system("docker stop $(docker ps -a -q)")
os.system("docker rm $(docker ps -a -q)")
'''
int_num = int(os.popen("ifconfig -a | grep veth | awk '{print $1}' | wc -l").read())
if int_num > 2:
    os.system("sudo ip link del veth0")
    os.system("sudo ip link del veth2")

else:
    os.system("sudo ip link del veth0")
