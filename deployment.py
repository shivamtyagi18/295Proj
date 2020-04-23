import os
import docker
import tarfile
import time
from io import BytesIO
import paramiko

hostname = "128.105.146.154"
username = "priganta"
password = "24091995Gp"
controller_ip = "155.98.38.240"
host_ip = "10.0.0.132"

#apiclient = docker.APIClient(base_url='tcp://10.0.0.132:2375',version="1.40")
#dockerClient = docker.DockerClient(base_url='tcp://10.0.0.132:2375',version="1.40")

def runSSH(host_ip,commands):
    # initialize the SSH client
    client = paramiko.SSHClient()
    k = paramiko.RSAKey.from_private_key_file("/Users/dharm/Downloads/id_rsa")
    
    # add to known hosts
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        #client.connect(hostname=host_ip, username=username, pkey = k)
        client.connect(hostname=host_ip, username="sdnnfv", password="1234")
    except:
        print("[!] Cannot connect to the SSH Server")
        exit()
    # execute the commands
    for command in commands:
        print("="*50, command, "="*50)
        stdin, stdout, stderr = client.exec_command('sudo '+ command , get_pty=True)
        stdin.write('1234\n')
        stdin.flush()
        print(stdout.read().decode())
        err = stderr.read().decode()
        if err:
            print(err)
            return False
    return True

def runContainer(host_ip,switch_id,protocol):
    
    apiclient = docker.APIClient(base_url='tcp://' + host_ip +':2375',version="1.40")
    dockerClient = docker.DockerClient(base_url='tcp://' + host_ip +':2375',version="1.40")
    
    try:
        container = dockerClient.containers.run('gantapritham4/sdnnfv',cap_add=['NET_ADMIN','NET_RAW'],detach=True,tty=True);
        runPigRelay(container)
        bridge_name = str(container.name)[:str(container.name).find('_')]
        commands = []
        commands.append('ovs-vsctl add-br ' + bridge_name)
        commands.append('ifconfig ' + bridge_name + ' up')
        commands.append('ovs-docker add-port '+ bridge_name +' eth1 ' + bridge_name)
        commands.append('ovs-docker add-port '+ bridge_name +' eth2 ' + bridge_name)
        commands.append('ip link add veth0 type veth peer name veth1')
        commands.append('ifconfig veth1 up')
        commands.append('ifconfig veth0 up')
        commands.append('ovs-vsctl add-port ' + bridge_name + ' veth1')
        commands.append('ovs-vsctl add-port vswitch1 veth0')
        commands.append('ovs-ofctl add-flow ' + bridge_name + ' in_port=3,actions=output:1')
        commands.append('ovs-ofctl add-flow ' + bridge_name + ' in_port=2,actions=output:3')

        if runSSH(host_ip,commands):
            startSnort(container)
        
        
        return True
        
    except docker.errors.ContainerError:
        print("Error in container execution")
        return False;
    
    except docker.errors.ImageNotFound:
        downloadImage(dockerClient,'gantapritham4/sdnnfv','latest')
        runContainer(switch_id,protocol)
    
    except docker.errors.APIError:
        print("Connection to the docker Deamon not successful")
        return False
    
def startSnort(container):
    try:
        print("="*25, "Runing snort in ",container.id, "="*25)
        result = container.exec_run('sh -c \'snort -A console -l /tmp -c /etc/snort/snort.conf -i eth0\'',stderr=True,stdout=True)
        print("exit-code: " + str(result.exit_code))

        #for line in result:
         #       print(line)
        return True
    except docker.errors.ContainerError:
        print("Error in container execution")
        return False;
    
def downloadImage(client,imageName,tag):
    try:
        image = client.get(imageName + ':' + tag)
        if image.id is not None:
            return True
    except docker.errors.ImageNotFound:
        print("Image Not found")
        return False
    except docker.errors.APIError:
        print("Connection to the docker Deamon not successful")
        return False

def runPigRelay(container):
    result = container.exec_run('sh -c "sed -i \'s/cont_ip/155.98.38.240/g\' pigrelay.py"')
    print(result)
    result2 = container.exec_run('sh -c \'python pigrelay.py\'')
    print(result2)
    
def changeRules(filename,container):
    print("Changing Rules for container:" + container.id)
    tarFile = getTarFile(filename)
    copyFile(container,tarFile)
    
    
def getTarFile(fileName):
    allRules = 'These are my rules'
    print (allRules)
    #write password to file
    pw_tarstream = BytesIO()
    pw_tar = tarfile.TarFile(fileobj=pw_tarstream, mode='w')
    file_data = allRules.encode('utf8')
    tarinfo = tarfile.TarInfo(name=str(fileName) + '.rules')
    tarinfo.size = len(file_data)
    tarinfo.mtime = time.time()
    pw_tar.addfile(tarinfo, BytesIO(file_data))
    pw_tar.close()
    
    return pw_tarstream

def copyFile(container,tarFile):
    print("Copying file to container :" + container.id)
    tarFile.seek(0)
    copy = apiclient.put_archive(
        container=container.id,
        path='/etc/snort/rules',
        data=tarFile
        )

def stopSnort(container):
    stop = container.exec_run('sh -c "ps aux | awk {\'print $11 $2\'} | grep ^snort"' ,stderr=True,stdout=True,workdir="/")
    process_id = str(stop.output, 'utf-8')[5:]
    print("killing procces with id" + process_id)
    result = container.exec_run('sh -c "kill ' + process_id +'"',stderr=True,stdout=True)
    print(result)
    
    
#container = dockerClient.containers.get('strange_goldstine')

#bridge = str(container.name)[:str(container.name).find('_')]
#commands = []
#commands.append('ovs-vsctl add-br ' + bridge)
#commands.append('ifconfig ' + bridge + ' up')

#runPigRelay(container)
#runSSH(commands)
#startSnort(container)
#stopSnort(container)
#changeRules("kiran",container)
runContainer(host_ip,'1234','tcp')
