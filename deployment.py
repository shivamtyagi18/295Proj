import os
import docker
import tarfile
import time
from io import BytesIO
import paramiko
import logging
import flask
import glob
import urllib3
import threading
from flask import request, jsonify

app = flask.Flask(__name__)
app.config["DEBUG"] = True

urllib3.disable_warnings()


#update username to use for login to Cloudlabs - must be a valid cloudlabs username
username = "dharma"

#update the controller's IP address here
controller_ip = "155.98.37.91"
i=0

#dictionary to keep track of flows for which a container is deployed and snort is started
deployed_list = []

#list for the lsit of containers being deployed 
in_progress = {}

#list to keep the list of containers ready to be used
ready = {}

#list for tar file of rules for Snort
tarFiles = {}
apiclient = None

@app.route('/', methods=['GET'])
def home():
    print("args are:" + str(request.args))
    return '<h1>Distant Reading Archive</h1><p>A prototype API for distant reading of science fiction novels.</p>'
    

#API to create a container inside a switch.
@app.route('/api/create', methods=['GET'])
def runContainer():
    start_time = time.time()
    host_ip = request.args['host_ip']

    #Function call to deploy a container
    if runContainerHelper(host_ip):
        print("----------------------- %s seconds --------------------------"  % (time.time() - start_time))
        return "True",200
    else:
        return "False",400


#Function definition to deploy a container inside the switch with IP address "host_ip"
def runContainerHelper(host_ip):
    if in_progress.get(host_ip) is None: 
        in_progress[host_ip] = []   #create in_progress
    print("="*25,"Starting Deployment in switch : " , str(host_ip),"="*25)
    try:
        if ready.get(host_ip) is None:
            ready[host_ip] = []     #create ready

        #code to calculate the existing veth in switch to deploy new veth. The format if vethx, x being a number.
        veth0 = str(len(ready[host_ip])*2)
        veth1 = str(len(ready[host_ip])*2+1)

        #TLS handshake for authentication to deploy a container.
        tls_config = docker.tls.TLSConfig(ca_cert='/usr/local/ca.pem' , client_cert=('/usr/local/client-cert.pem', '/usr/local/client-key.pem'))
        #apiclient = docker.APIClient(base_url='tcp://' + host_ip +':2376',version="1.39",tls=tls_config)
        dockerClient = docker.DockerClient(base_url='tcp://' + host_ip +':2376',version="1.39",tls=tls_config)
        container = dockerClient.containers.run('dharmadheeraj/sdnnfv',cap_add=['NET_ADMIN','NET_RAW'],detach=True,tty=True);
        in_progress.get(host_ip).append(container.id)   #append container ID to in_progress as the deployment is in process
        print("Container Deployed with id: " + container.id)
        #runPigRelay(container)
        bridge_name = str(container.name)[:str(container.name).find('_')]   #using container name to make a bridge name
        print('bridge Name : ', bridge_name)
        print("Adding Commands")

        #commands to deploy a bridge for container, connect the container and bridge, and add flow rules to that bridge
        commands = []
        commands.append('ovs-vsctl add-br ' + bridge_name)
        #commands.append('ifconfig ' + bridge_name + ' up')
        commands.append('ovs-ofctl add-flow ' + bridge_name + ' dl_type=0x86dd,actions=drop')
        commands.append('ovs-ofctl add-flow ' + bridge_name + ' dl_type=0x0806,actions=drop')
        commands.append('ovs-docker add-port '+ bridge_name +' eth1 ' + str(container.name))
        commands.append('ovs-docker add-port '+ bridge_name +' eth2 ' + str(container.name))
        commands.append('ip link add veth' + veth0 +' type veth peer name veth' + veth1)
        commands.append('ifconfig veth' + veth0 +' up')
        commands.append('ifconfig veth' + veth1 +' up')
        commands.append('ovs-vsctl add-port ' + bridge_name + ' veth' + veth1)
        commands.append('ovs-vsctl add-port ovs-lan veth' + veth0)
        commands.append('ovs-ofctl add-flow ' + bridge_name + ' in_port=3,actions=output:1')
        commands.append('ovs-ofctl add-flow ' + bridge_name + ' in_port=2,actions=output:3')
        print("Starting ssh commands")

        #Create a SSH connection to run the above commands
        if runSSH(host_ip,commands):
            ready.get(host_ip).append(container.id)     #once container is ready, append the container ID to ready list and remove it from in_progress
            in_progress.get(host_ip).remove(container.id)
            print("Container Ready on Host:" + host_ip)
            return True

        return False

    except docker.errors.ContainerError:
        print("Error in container execution")
        return False

    #Look for the specific docker image. The imahe should already be present inside the switch to reduce the delays.
    except docker.errors.ImageNotFound:
        if downloadImage(dockerClient,'dharmadheeraj/sdnnfv','latest'):
            runContainer(host_ip,switch_id,protocol)
        else:
            print("Error Downloading Image")
            return False

    except docker.errors.APIError:
        print("Connection to the docker Deamon not successful")
        return False

#Function definition to initiate a SSH connection from controller to switch
def runSSH(host_ip,commands):
    # initialize the SSH client
    client = paramiko.SSHClient()
    print("Getting Private token")
    try:
        k = paramiko.RSAKey.from_private_key_file("/usr/local/dharma")  #Make sure right private key file is mapped. The file name is dharma in this case
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



#API call to start snort inside a container
@app.route('/api/start', methods=['GET'])
def startSnort():
    start_time = time.time()

    #fetch packet parameters to keep track of flow and use right set of Snort rules.
    host_ip = request.args['host_ip']
    src_ip = request.args['src_ip']
    dst_ip = request.args['dst_ip']
    src_port = request.args['src_port']
    dst_port = request.args['dst_port']
    protocol = request.args['protocol']
    
    if checkDeployment(src_ip,dst_ip,src_port,dst_port,protocol):       #function to check if any container deployed in a switch for a specific flow
        return "Already Runnning Container",200                         #if container present, return. Else continue
    
    try:
        t = threading.Thread(target=runContainerHelper,args=(host_ip,))
        t.start()
    except:
        print("Error: unable to start thread")
    
    setid = getSnortSet(src_port,dst_port,protocol)             #function to fetch the set number of Snort rules

    deployment = {"src_ip": src_ip, "dst_ip":dst_ip, "src_port": src_port, "dst_port": dst_port, "protocol": protocol}
    deployed_list.append(deployment)                            #append the flow params to the dictionary

    while len(ready.get(host_ip)) == 0:
        time.sleep(1) 
    container_id = ready.get(host_ip).pop(0)
    
    print("="*25,"Starting Snort Run on Host:" + host_ip + " and container : " + container_id,"="*25)
    try:

        #tls authentication to start snort inside a container
        tls_config = docker.tls.TLSConfig(ca_cert='/usr/local/ca.pem' , client_cert=('/usr/local/client-cert.pem', '/usr/local/client-key.pem'))
        apiclient = docker.APIClient(base_url='tcp://' + host_ip +':2376',version="1.39",tls=tls_config)
        dockerClient = docker.DockerClient(base_url='tcp://' + host_ip +':2376',version="1.39",tls=tls_config)
        container = dockerClient.containers.get(container_id)
        runPigRelay(container)
        #command = 'sh -c '
        #command += '\'snort -A unsock -l /tmp -c /etc/snort/snort.conf -Q -i eth1:et2\''
        print("Runing snort in : %s",container.id)
        result = container.exec_run('sh -c \'snort -A unsock -l /tmp -c /etc/snort/set10_snort.conf -Q -i eth1:eth2\'',detach=True,tty=True)
        print("Finished Running snort with exit-code: %s" + str(result.exit_code))
        print("Deployed Container for:" + str(deployment))
        print("Total Deployments:" + str(deployed_list))
        print("----------------------- %s seconds --------------------------"  % (time.time() - start_time))
        return "True",201

        #for line in result:
        #       print('%s',line)
        #return True
    except docker.errors.ContainerError:
        print("Error in container execution")
        return "False",400;
    
    except docker.errors.APIError:
        print("Connection to the docker Deamon not successful")
        return "False",400


#Function definition to select a snort rule set based on packet params
def getSnortSet(scr_port,dst_port,protocol):
    print("+"*10, "Protocol value :", str(protocol), "+"*10)
    
    #decision logic to select the set number. Only basic selected, more intricate logic to be written
    if(protocol == 'tcp'):
        return 'set18'
    else:
        return 'set10'

#Function to check if there's a container running for that specific flow
def checkDeployment(src_ip,dst_ip,src_port,dst_port,protocol):
    test1 = {"src_ip": src_ip, "dst_ip":dst_ip, "src_port": src_port, "dst_port": dst_port, "protocol": protocol}
    test2 = {"src_ip": dst_ip, "dst_ip":src_ip, "src_port": dst_port, "dst_port": src_port, "protocol": protocol}
    for i in range(len(deployed_list)): 
        if test1==deployed_list[i] or test2==deployed_list[i]:
            print("Deployment already exist in the switch")
            return True
    return False  

#Function definition to start Pigrelay code
def runPigRelay(container):
    result = container.exec_run('sh -c "sed -i \'s/172.17.0.1/155.98.37.91/g\' pigrelay.py"')
    print("Changed pigrelay file with error code:" + str(result.exit_code))
    result2 = container.exec_run('sh -c \'python pigrelay.py\'',detach=True,tty=True)
    print("Started Pigrelay with exit code:" + str(result2.exit_code))
    return
   

#Function definitions to change the rules files inside containers
def changeRules(filename,container):
    print("Changing Rules for container:" + container.id)
    tarFile = tarFiles.get(filename)
    copyFile(container,tarFile)
    
    
def getTarFile(fileName):
    print("Making a tar file for: " + fileName)
    demofile = open('/usr/local/295Proj/' + fileName , "r")
    #print (allRules)
    #write password to file
    pw_tarstream = BytesIO()
    pw_tar = tarfile.TarFile(fileobj=pw_tarstream, mode='w')
    file_data = demofile.read().encode('utf8')
    tarinfo = tarfile.TarInfo(name=str(fileName))
    tarinfo.size = len(file_data)
    tarinfo.mtime = time.time()
    pw_tar.addfile(tarinfo, BytesIO(file_data))
    pw_tar.close()
    tarFiles[fileName] = pw_tarstream

def copyFile(container,tarFile):
    print("Copying file to container :" + container.id)
    tarFile.seek(0)
    copy = apiclient.put_archive(
        container=container.id,
        path='/etc/snort/rules',
        data=tarFile
        )


#Function to restart snort inside a container. using container ID
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

os.chdir("/usr/local/295Proj")
for file in glob.glob("*.rules"):
    getTarFile(file)

print("No Of Rules Files: " + str(len(tarFiles)))

print("App starting with Controller IP: " + controller_ip)

app.run()
