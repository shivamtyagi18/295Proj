import os
import docker
import tarfile
import time
from io import BytesIO
import paramiko
import logging
import flask
from flask import request, jsonify

app = flask.Flask(__name__)
app.config["DEBUG"] = True


#logging.basicConfig(filename='deployment.log', filemode='w', level=logging.DEBUG,format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
username = "dharma"
controller_ip = "155.98.37.91"
i=0


@app.route('/', methods=['GET'])
def home():
    print("args are:" + str(request.args))
    return '<h1>Distant Reading Archive</h1><p>A prototype API for distant reading of science fiction novels.</p>'
    
@app.route('/api/create', methods=['GET'])
def runContainer():
    host_ip = request.args['host_ip']
    switch_id = request.args['switch_id']
    protocol = request.args['protocol']
    
    print("Starting Deployment in switch : %s" , str(host_ip))
    apiclient = docker.APIClient(base_url='tcp://' + host_ip +':2375',version="1.40")
    dockerClient = docker.DockerClient(base_url='tcp://' + host_ip +':2375',version="1.40")
    global i
    if i==0: 
        try:
            i = i+1
            container = dockerClient.containers.run('dharmadheeraj/sdnnfv',cap_add=['NET_ADMIN','NET_RAW'],detach=True,tty=True);
            print("Container Deployed with id: %s" + container.id)
            runPigRelay(container)
            bridge_name = str(container.name)[:str(container.name).find('_')]
            print('bridge Name : %s', bridge_name)
            print("Adding Commands")
            commands = []
            commands.append('ovs-vsctl add-br ' + bridge_name)
            commands.append('ifconfig ' + bridge_name + ' up')
            commands.append('ovs-docker add-port '+ bridge_name +' eth1 ' + str(container.name))
            commands.append('ovs-docker add-port '+ bridge_name +' eth2 ' + str(container.name))
            commands.append('ip link add veth0 type veth peer name veth1')
            commands.append('ifconfig veth1 up')
            commands.append('ifconfig veth0 up')
            commands.append('ovs-vsctl add-port ' + bridge_name + ' veth1')
            commands.append('ovs-vsctl add-port ovs-lan veth0 -- set interface veth0 ofport_request=3')
            commands.append('ovs-ofctl add-flow ' + bridge_name + ' in_port=3,actions=output:1')
            commands.append('ovs-ofctl add-flow ' + bridge_name + ' in_port=2,actions=output:3')
            print("Starting ssh commands")
            if runSSH(host_ip,commands):
                if startSnort(container):
                    return "True",200
                
            return "False",400
        
        except docker.errors.ContainerError:
            print("Error in container execution")
            return "False",400;
    
        except docker.errors.ImageNotFound:
            if downloadImage(dockerClient,'dharmadheeraj/sdnnfv','latest'):
                runContainer(host_ip,switch_id,protocol)
            else:
                print("Error Downloading Image")
                return "False",400
    
        except docker.errors.APIError:
            print("Connection to the docker Deamon not successful")
            return "False",400
    else:
        print("Ignoring Docker Run")
        return "Ignore",200

    
def runSSH(host_ip,commands):
    # initialize the SSH client
    client = paramiko.SSHClient()
    print("Getting Private token")
    try:
        k = paramiko.RSAKey.from_private_key_file("/usr/local/dharma")
        # add to known hosts
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # Initiate Connection
        print("Initiating Conection")
        client.connect(hostname=host_ip, username=username, pkey = k)
        print("Connection Successfull")
        #client.connect(hostname=host_ip, username="sdnnfv", password="1234")
    except:
        print("[!] Cannot connect to the SSH Server")
        return False
    # execute the commands
    for command in commands:
        print(command)
        stdin, stdout, stderr = client.exec_command('sudo '+ command , get_pty=True)
        #stdin.write('1234\n')
        #stdin.flush()
        print('Output is :%s',stdout.read().decode())
        err = stderr.read().decode()
        if err:
            print(err)
            return False
    return True
    
def startSnort(container):
    try:
        print("Runing snort in : %s",container.id)
        result = container.exec_run('sh -c \'snort -A unsock -l /tmp -c /etc/snort/snort.conf -Q -i eth1:eth2\'',stderr=True,stdout=True)
        print("Finished Running snort with exit-code: %s" + str(result.exit_code))

        for line in result:
                print('%s',line)
        return True
    except docker.errors.ContainerError:
        print("Error in container execution")
        return False;
    
def downloadImage(client,imageName,tag):
    try:
        print("="*25, "Downloading Docker Image ",imageName, "="*25)
        image = client.images.pull(repository=imageName,tag=tag)
        if image.id is not None:
            return True
    except docker.errors.ImageNotFound:
        print("Image Not found")
        return False
    except docker.errors.APIError:
        print("Connection to the docker Deamon not successful")
        return False

def runPigRelay(container):
    result = container.exec_run('sh -c "sed -i \'s/172.17.0.1/155.98.37.91/g\' pigrelay.py"')
    print("Changed pigrelay file with error code:" + str(result.exit_code))
    result2 = container.exec_run('sh -c \'python pigrelay.py\'',detach=True,tty=True)
    print("Started Pigrelay with exit code:" + str(result2.exit_code))
    return
    
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
#runContainer(host_ip,'1234','tcp')





print("App starting with Controller IP: " + controller_ip)

app.run()
