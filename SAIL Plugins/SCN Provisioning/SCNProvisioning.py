from shutil import get_archive_formats
import time

from watchdog.observers import Observer

from watchdog.events import PatternMatchingEventHandler


from azure.identity import AzureCliCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network.v2020_06_01.models import NetworkSecurityGroup
import os
import requests

from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient, __version__
import json

from random import *

import mysql.connector
from mysql.connector import errorcode

from datetime import datetime

#Initializing Service Principal
client_id="a547fa4d-296c-4c1c-ab90-c5010bd1ae5f"
client_secret="Ne28Q~cXnQB_FVv4~3Wy-VgzfAVPOW3NVI3GTbkI"
tenant_id="3e74e5ef-7e6a-4cf0-8573-680ca49b64d8"

#Folder Monitoring Thread
my_observer = Observer()

#Path to monitor for json files please change this path to your monitoring path

path = "C:\\Users\PriyanshuKumar\OneDrive - HANU SOFTWARE SOLUTIONS INDIA PRIVATE LIMITED\MY Codes\Python Secure AI\SCN Provisioning\Monitor"

patterns = ["*.json"]

ignore_patterns = None

ignore_directories = False

case_sensitive = True

my_event_handler = PatternMatchingEventHandler(patterns, ignore_patterns, ignore_directories, case_sensitive)

#Authentication token for azure this token will be used by rest API's to read and write to azure

def auth():
    try:
        url = "https://login.microsoftonline.com/"+tenant_id+"/oauth2/token"

        payload='grant_type=client_credentials&client_id='+client_id+'&client_secret='+client_secret+'&resource=https%3A%2F%2Fmanagement.azure.com%2F'
        headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Cookie': 'fpc=AlH-2ZgjN6hHoIX-qCTF7NzsSf-3AQAAALSOb9gOAAAA; stsservicecookie=estsfd; x-ms-gateway-slice=estsfd'
        }

        response = requests.request("GET", url, headers=headers, data=payload)

        data=response.text
        jsondata=json.loads(data)
        token=jsondata["access_token"]
        return token
    
    except:
        print("Token can't be generated")

#Dependent function for monitoring 

def key_num(d):

   return sum(not isinstance(b, dict) or 1 + key_num(b) for b in d.values())

# Monitoring Function

def on_created(event):
    print('File Encountered')
    #Creating a lock file until the contents of json file is fully written and waiting for the lock file to be deleted to proceed
    lock_file = event.src_path + ".lock"

    open(lock_file,"w+")

    f1=True

    while f1:
        try:
            f = open(event.src_path,"r")
            data = json.load(f)
            # The no of keys that must be in incoming json file please change the value accordingly if json file changes later
            if (key_num(data)==23):
                f1=False
                os.remove(lock_file)
            f.close()
        except:
            pass

    if(os.path.exists(lock_file)):
        pass
    else:
        print(".lock file removed")

    jsondata=open(event.src_path,"r")
    data=json.load(jsondata)

    try:
        #Initializing the variables from input json file
        ROI=data['InitializationParameters']['ResearchOrganizationIdentifier']
        DOOI=data['InitializationParameters']['DataOwnerOrganizationIdentifier']
        DCI=data['InitializationParameters']['DigitalContractTdentifier']
        DI=data['InitializationParameters']['DatasetIdentifier']
        TKAC="xyzxyzxyxxyxzzzyxzy"
        EAESK="adfgjkloiuytdfrjvft"
        RORP=data['InitializationParameters']['ResearchOrganizationRsaAuditPublicKey']
        DOORP=data['InitializationParameters']['DataOwnerOrganizationRsaAuditPublicKey']
        AORP=data['InitializationParameters']['AuditorOrganizationRsaAuditPublicKey']
        SORP=data['InitializationParameters']['SailOrganizationRsaAuditPublicKey']
        EADEK=data['InitializationParameters']['EncryptedAesDataExchangeKey']
        IPSAIL="10.10.10.10"
        ECB=blob_fetch()
        token=auth()
        guid="12345678123456781234567812345678"
        
        vm_name=data['vm_name']
        rg_name=data['rg_name']
        nsg_name=data['nsg_name']
        vnet_name=data['vnet_name']
        vm_size=data['Request']['VirtualMachineType']
        loc=data['Request']['Region']
        now = datetime.now()
        now=str(now)  
        insert_db(vm_name,guid,'Provisioning',now)
        status=res_creation(rg_name,vnet_name,nsg_name,vm_name,vm_size,loc,guid)
        vm_status=fetch_vm_status_from_azure(status[0],token)
        now = datetime.now()
        now=str(now)
        if status[1]!="OK":
            insert_db(vm_name,guid,"Not Provisioned error",now)  
        insert_db(vm_name,status[0],vm_status,now)
        json_write(status[0],ROI,DOOI,DCI,DI,TKAC,EAESK,ECB,RORP,DOORP,AORP,SORP,EADEK,IPSAIL)

    except: 
        print("Missing Json Values")
    #print(vm_name)

    #print(f"hey, {event.src_path} ")

# Fetching VM status from azure
def fetch_vm_status_from_azure(ID,token):
    url = "https://management.azure.com"+ID+"/InstanceView?api-version=2022-03-01"
    payload = {}
    headers = {
        'Authorization': 'Bearer ' + token,
        }
    response = requests.request("GET", url, headers=headers, data=payload)
    result = response.text
    jsondata = json.loads(result)
    values = jsondata
    now_status=values["statuses"][1]['code']
    now_status=now_status.split('/')
    now_status=now_status[-1]
    print(now_status)
    return now_status

# Creating VM and dependent resources in azure 

def res_creation(rg_name,vnet_name,nsg_name,vm_name,vm_size,loc,guid):
    try:

        credential = AzureCliCredential()

    # Retrieve subscription ID from environment variable.
        subscription_id = "b7a46052-b7b1-433e-9147-56efbfe28ac5"


        # 1 - create a resource group

        # Get the management object for resources, this uses the credentials from the CLI login.
        resource_client = ResourceManagementClient(credential, subscription_id)

        # Set constants we need in multiple places.  You can change these values however you want.
        rg_name=rg_name+"-sail-eus-prod-"+guid
        RESOURCE_GROUP_NAME = rg_name
        LOCATION = loc

        #Checking if RG name is already present or not in that location
        rg_list = resource_client.resource_groups.list()

        for rgs in list(rg_list):
            if rgs.name==RESOURCE_GROUP_NAME and rgs.location==LOCATION:
                return "RG with this name already exist in the specified lcoation "
        # create the resource group.
        rg_result = resource_client.resource_groups.create_or_update(RESOURCE_GROUP_NAME,
            {
                "location": LOCATION
            }
        )

        print(f"Provisioned resource group {rg_result.name} in the {rg_result.location} region")


        # 2 - provision the virtual network


        # Network and IP address names
        VNET_NAME = vnet_name+"-sail-eus-prod-"+guid
        SUBNET_NAME = vnet_name +"-SNET01"
        IP_NAME = vm_name+"-IP01"+"-sail-eus-prod"
        IP_CONFIG_NAME = vm_name+ "-IPCONFIG01"+"-sail-eus-prod"
        NIC_NAME = vm_name+"-NIC01"+"-sail-eus-prod"

        # Get the management object for the network
        network_client = NetworkManagementClient(credential, subscription_id)


        #Checking if VNet is already present in that Resource Group
        net_list=network_client.virtual_networks.list(RESOURCE_GROUP_NAME)

        for netw in list(net_list):
            if netw.name==VNET_NAME:
                return "VNET with this name is already present in the specified Resource Group"

        # Create the virtual network 
        poller = network_client.virtual_networks.begin_create_or_update(RESOURCE_GROUP_NAME,
            VNET_NAME,
            {
                "location": LOCATION,
                "address_space": {
                    "address_prefixes": ["10.0.0.0/16"]
                }
            }
        )

        vnet_result = poller.result()
        

        print(f"Provisioned virtual network {vnet_result.name} with address prefixes {vnet_result.address_space.address_prefixes}")

        # 3 - Create the subnet
        poller = network_client.subnets.begin_create_or_update(RESOURCE_GROUP_NAME, 
            VNET_NAME, SUBNET_NAME,
            { "address_prefix": "10.0.0.0/24" }
        )
        subnet_result = poller.result()

        print(f"Provisioned virtual subnet {subnet_result.name} with address prefix {subnet_result.address_prefix}")

        # 4 - Create the IP address
        """"
        poller = network_client.public_ip_addresses.begin_create_or_update(RESOURCE_GROUP_NAME,
            IP_NAME,
            {
                "location": LOCATION,
                "sku": { "name": "Standard" },
                "public_ip_allocation_method": "Static",
                "public_ip_address_version" : "IPV4"
            }
        )

        ip_address_result = poller.result()

        print(f"Provisioned public IP address {ip_address_result.name} with address {ip_address_result.ip_address}")
        """
        # Creating the Network Security Group with default values
        nsg_name=vm_name+"-"+nsg_name+"-sail-eus-prod"
        
        nsg_params = NetworkSecurityGroup(id=nsg_name,location=LOCATION)
        nsg = network_client.network_security_groups.begin_create_or_update(RESOURCE_GROUP_NAME, nsg_name, parameters=nsg_params)
        nsg=nsg.result()

        # 5 - Create the network interface client
        poller = network_client.network_interfaces.begin_create_or_update(RESOURCE_GROUP_NAME,
            NIC_NAME, 
            {
                "location": LOCATION,
                "ip_configurations": [ {
                    "name": IP_CONFIG_NAME,
                    "subnet": { "id": subnet_result.id }
                    #"public_ip_address": {"id": ip_address_result.id }
                }],
                "network_security_group": {
                "id": nsg.id
            }

            }
            
        )

        nic_result = poller.result()

        print(f"Provisioned network interface client {nic_result.name}")

        # 6 - Create the virtual machine

        # Get the management object for virtual machines
        compute_client = ComputeManagementClient(credential, subscription_id)

        VM_NAME = vm_name+"-sail-eus-prod"+guid
        USERNAME = "pythonazureuser"
        PASSWORD = "ChangeM3N0w!"

        print(f"Provisioning virtual machine {VM_NAME}; this operation might take a few minutes.")

        # Create the VM (Ubuntu 18.04 VM)
        # on a Standard DS1 v2 plan with a public IP address and a default virtual network/subnet.

        poller = compute_client.virtual_machines.begin_create_or_update(RESOURCE_GROUP_NAME, VM_NAME,
            {
                "location": LOCATION,
                "storage_profile": {
                    'image_reference': {
                    'id' : '/subscriptions/b7a46052-b7b1-433e-9147-56efbfe28ac5/resourceGroups/NginxImageStorageRg/providers/Microsoft.Compute/images/securecomputationnode'
                }
                },
                "hardware_profile": {
                    "vm_size": vm_size
                },
                "os_profile": {
                    "computer_name": VM_NAME,
                    "admin_username": USERNAME,
                    "admin_password": PASSWORD
                },
                "network_profile": {
                    "network_interfaces": [{
                        "id": nic_result.id,
                    }]
                }
            }
        )

        vm_result = poller.result()
        vm_id=vm_result.id

        print(f"Provisioned virtual machine {vm_result.name}")
        return [vm_id,"OK"]
    except:
        print("Authentication Error")
        return ['None',"Authentication Error"]


# Inserting new status in the database
def insert_db(vm_name,vm_id,state,dt):
    # Intializing connection parameter to connect to the database
    config = {
    'host':'scntest.mysql.database.azure.com',
    'user':'hanuadmin@scntest',
    'password':'123@hanu123@HANU',
    'database':'sail_test_db',
    'client_flags': [mysql.connector.ClientFlag.SSL],
    'ssl_ca': 'C:\\Users\hanuadmin\Downloads\Cer\DigiCertGlobalRootG2.crt.pem'
    }

    # Construct connection string and intialize database pointer

    try:
        conn = mysql.connector.connect(**config)
        print("Connection established")
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("Something is wrong with the user name or password")
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print("Database does not exist")
        else:
            print(err)
    else:
        cursor = conn.cursor()

    # Inserting data into table
    cursor.execute("INSERT INTO scn_provisioning_plugin (vm_name, resource_id,resoure_state,time) VALUES (%s, %s, %s,%s);", (vm_name,vm_id,state,dt))
    print("Inserted",cursor.rowcount,"row(s) of data.")
    

    # Cleanup intialized database pointer
    conn.commit()
    cursor.close()
    conn.close()
    print("Done.")


# Writing the Output Initialization Vectors
def json_write(vm_id,ROI,DOOI,DCI,DI,TKAC,EAESK,ECB,RORP,DOORP,AORP,SORP,EADEK,IPSAIL):

    dictionary ={

        "VirtualMachineIdentifier": vm_id,
        "ResearchOrganizationIdentifier":ROI,
        "DataOwnerOrganizationIdentifier":DOOI,
        "DigitalContractTdentifier":DCI,
        "DatasetIdentifier":DI,
        "TlsKeysAndCert":TKAC,
        "EncryptedAesKey":EAESK,
        "EncryptedCompressedBinaries":ECB,
        "ResearchOrganizationRsaAuditPublicKey":RORP,
        "DataOwnerOrganizationRsaAuditPublicKey":DOORP,
        "AuditorOrganizationRsaAuditPublicKey":AORP,
        "SailOrganizationRsaAuditPublicKey":SORP,
        "EncryptedAesDataExchangeKey":EADEK,
        "IpAddressOfSailPlatformServices":IPSAIL
    }

    json_string = json.dumps(dictionary)


    with open("IV.json", "w") as o:

        o.write(json_string)
        
# Container name
CONTAINERNAME = "binaryfiles"
 
# Fetching the images from azure blob
def blob_fetch():
    container = ContainerClient.from_connection_string(conn_str="DefaultEndpointsProtocol=https;AccountName=test3storage;AccountKey=ulkTo6nj49BOTf+8vFafDMSrWowuTBvzkgH+Umf+e1HngiTD8DblBQ7gE2vMXPIOblC735M4lEfF+AStRa3PcA==;EndpointSuffix=core.windows.net", container_name = CONTAINERNAME)
    blob_list = container.list_blobs()
    sorted_blob_list = sorted(blob_list,key=lambda x: x.creation_time, reverse=True)
    print(sorted_blob_list[0].name)
    blob_download(sorted_blob_list[0].name)
        

# Downloading the blob file from azure conatainer
def blob_download(file_name):
    
    blob_service_client = BlobServiceClient.from_connection_string("DefaultEndpointsProtocol=https;AccountName=test3storage;AccountKey=ulkTo6nj49BOTf+8vFafDMSrWowuTBvzkgH+Umf+e1HngiTD8DblBQ7gE2vMXPIOblC735M4lEfF+AStRa3PcA==;EndpointSuffix=core.windows.net")
    local_path = r"C:\Downloads\Documents"
    download_file_path = os.path.join(local_path, str.replace(file_name ,'.rar', 'DOWNLOAD.rar'))
    blob_client = blob_service_client.get_container_client(container= CONTAINERNAME) 
    print("\nDownloading blob to \n\t" + download_file_path)

    with open(download_file_path, "wb") as download_file:
        download_file.write(blob_client.download_blob(file_name).readall())

#Main Function
if __name__ == "__main__":


    my_event_handler.on_created = on_created

    my_observer.schedule(my_event_handler, path, recursive=True)

    my_observer.start()

    try:

        while True:

            time.sleep(1)

    except KeyboardInterrupt:

        my_observer.stop()

        my_observer.join()
