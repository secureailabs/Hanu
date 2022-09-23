from distutils.log import error
import time

from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler


from azure.identity import ClientSecretCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.network.models import VirtualNetworkPeering
from azure.mgmt.network.models import SubResource
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network.v2020_06_01.models import NetworkSecurityGroup
from azure.mgmt.network.models import Subnet
import os

from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient, __version__
import json

from random import *
import requests

import mysql.connector
from mysql.connector import errorcode

from datetime import datetime


#Initializing Service Principal
client_id="5d2ea8c7-09ea-41ce-80b6-030777fce49b"
client_secret="3PG8Q~0Jh1HU~Y3DoadZPUb5noEiJnesEJGXScLl"
tenant_id="3e74e5ef-7e6a-4cf0-8573-680ca49b64d8"

#Folder Monitoring Thread
my_observer = Observer()

#Path to monitor for json file
path ="/home/sailadmin/Platform_Provisioning_plugin/Monitor" 
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
    print('Json File Encountered in the specified path')

    lock_file = event.src_path + ".lock"

    open(lock_file,"w+")

    f1=True
    while f1:
        try:
            f = open(event.src_path,"r")
            data = json.load(f)
            #key_num(data)
            if (key_num(data)==16):
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

    TKAC="xyzxyzxyxxyxzzzyxzy"
    EAESK="adfgjkloiuytdfrjvft"
    IPSAIL="10.10.10.10"
    ECB=blob_fetch()
    token=auth()

    vm_name=data['vm_name']
    #nic_name=data['nic_name']
    rg_name=data['rg_name']
    nsg_name=data['nsg_name']
    vnet_name=data['vnet_name']
    vm_size=data['Request']['VirtualMachineType']
    loc=data['Request']['Region']
    guid=fetch_guid() 
    insert_db(vm_name,guid,guid,"Provisioning")
    status=api_res_creation(vm_size,loc,guid)
    vm_status=fetch_vm_status_from_azure(status[0],token)
    vm_name=status[0].split('/')
    vm_name=vm_name[-1]
    if status[1]!="OK":
        now = datetime.now()
        now=str(now)
        insert_db(vm_name,guid,guid,"Not Provisioned") 
    insert_db(vm_name,guid,status[0],vm_status)
    json_write(status[0],TKAC,EAESK,ECB,IPSAIL)

  

#Adding New PIP to Azure Firewall
def add_pip_to_fw(guid,pip_id):
    token=auth()
    y={
        "name": guid,
        "type": "Microsoft.Network/azureFirewalls/azureFirewallIpConfigurations",
        "properties": {
            "publicIPAddress": {
                "id": pip_id
            }
        }
    }
    try:
        url = "https://management.azure.com//subscriptions/6e7f356c-6059-4799-b83a-c4744e4a7c2e/resourceGroups/rg-sail-wus-hub-001/providers/Microsoft.Network/azureFirewalls/afw-sail-wus?api-version=2022-01-01"
        headers = {
            'Authorization': 'Bearer ' + token,
            'Accept' : 'application/json', 
            'Content-Type' : 'application/json'
            }
        response = requests.request("GET", url, headers=headers)
        result = response.text
        jsondata = json.loads(result)
        jsondata["properties"]["ipConfigurations"].append(y)
        with open('add_pip_to_hubfw.json', 'w+') as json_file:
            json.dump(jsondata, json_file) 
        json_file.close()
        with open('add_pip_to_hubfw.json', 'r+') as json_file:
            data = json.load(json_file)
        json_file.close()             
    except error:
        print(error)
    try:
        url = "https://management.azure.com//subscriptions/6e7f356c-6059-4799-b83a-c4744e4a7c2e/resourceGroups/rg-sail-wus-hub-001/providers/Microsoft.Network/azureFirewalls/afw-sail-wus?api-version=2022-01-01"
        headers = {
            'Authorization': 'Bearer ' + token,
            'Accept' : 'application/json', 
            'Content-Type' : 'application/json'
            }
        response = requests.request("PUT", url, headers=headers, data=json.dumps(data))
        result = response.text
        jsondata = json.loads(result)
        print("Public IP Added Successfully To Azure Firewall")
    except error:
        print(error)

# Adding Newly created Webfront Dnat rule to firewall policy
def add_webft_dnat_fw_rule(guid,p_ip,pvt_ip,port):
    token=auth()
    y= {
        "ruleType": "NatRule",
        "name": guid,
        "translatedAddress": pvt_ip,
        "translatedPort": port,
        "ipProtocols": [
            "TCP"
        ],
        "sourceAddresses": [
            "*"
        ],
        "sourceIpGroups": [],
        "destinationAddresses": [
            p_ip
        ],
        "destinationPorts": [
            port
        ]
    }
    try:
        url = "https://management.azure.com//subscriptions/6e7f356c-6059-4799-b83a-c4744e4a7c2e/resourceGroups/rg-sail-wus-hub-001/providers/Microsoft.Network/firewallPolicies/afwpol-sail-wus-001/ruleCollectionGroups/WEBFRONTRuleCollectionGroup?api-version=2022-01-01"
        headers = {
            'Authorization': 'Bearer ' + token,
            'Accept' : 'application/json', 
            'Content-Type' : 'application/json'
            }
        response = requests.request("GET", url, headers=headers)
        result = response.text
        jsondata = json.loads(result)
        jsondata["properties"]["ruleCollections"][0]["rules"].append(y)
        with open('add_webftnatrule_to_hubfw.json', 'w+') as json_file:
            json.dump(jsondata, json_file) 
        json_file.close()
        with open('add_webftnatrule_to_hubfw.json', 'r+') as json_file:
            data = json.load(json_file)
        json_file.close()
    except error:
        print(error)
    url = "https://management.azure.com//subscriptions/6e7f356c-6059-4799-b83a-c4744e4a7c2e/resourceGroups/rg-sail-wus-hub-001/providers/Microsoft.Network/firewallPolicies/afwpol-sail-wus-001/ruleCollectionGroups/WEBFRONTRuleCollectionGroup?api-version=2022-01-01"
    headers = {
        'Authorization': 'Bearer ' + token,
        'Accept' : 'application/json', 
        'Content-Type' : 'application/json'
        }
    response = requests.request("PUT", url, headers=headers, data=json.dumps(data))
    result = response.text
    jsondata = json.loads(result)
    print("Added Dnat Rule for WEBFRONT Successfully")


# Adding Newly created API Dnat rule to firewall policy
def add_api_dnat_fw_rule(guid,p_ip,pvt_ip,port):
    token=auth()
    y= {
        "ruleType": "NatRule",
        "name": guid,
        "translatedAddress": pvt_ip,
        "translatedPort": port,
        "ipProtocols": [
            "TCP"
        ],
        "sourceAddresses": [
            "*"
        ],
        "sourceIpGroups": [],
        "destinationAddresses": [
            p_ip
        ],
        "destinationPorts": [
            port
        ]
    }
    try:
        url = "https://management.azure.com//subscriptions/6e7f356c-6059-4799-b83a-c4744e4a7c2e/resourceGroups/rg-sail-wus-hub-001/providers/Microsoft.Network/firewallPolicies/afwpol-sail-wus-001/ruleCollectionGroups/APIRuleCollectionGroup?api-version=2022-01-01"
        headers = {
            'Authorization': 'Bearer ' + token,
            'Accept' : 'application/json', 
            'Content-Type' : 'application/json'
            }
        response = requests.request("GET", url, headers=headers)
        result = response.text
        jsondata = json.loads(result)
        jsondata["properties"]["ruleCollections"][0]["rules"].append(y)
        with open('add_apinatrule_to_hubfw.json', 'w+') as json_file:
            json.dump(jsondata, json_file) 
        json_file.close()
        with open('add_apinatrule_to_hubfw.json', 'r+') as json_file:
            data = json.load(json_file)
        json_file.close()
    except error:
        print(error)
    

    url = "https://management.azure.com//subscriptions/6e7f356c-6059-4799-b83a-c4744e4a7c2e/resourceGroups/rg-sail-wus-hub-001/providers/Microsoft.Network/firewallPolicies/afwpol-sail-wus-001/ruleCollectionGroups/APIRuleCollectionGroup?api-version=2022-01-01"
    headers = {
        'Authorization': 'Bearer ' + token,
        'Accept' : 'application/json', 
        'Content-Type' : 'application/json'
        }
    response = requests.request("PUT", url, headers=headers, data=json.dumps(data))
    result = response.text
    jsondata = json.loads(result)
    print("Added Dnat Rule for API Successfully")

#Fetching Unique ID for every new Plugins
def fetch_guid():
    import uuid 
    guid=uuid.uuid4()
    return str(guid)

#To get the provisioning status of new API Plugin from azure 
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
    return now_status

#Creating API Plugin and its dependent resources in azure
def api_res_creation(vm_size,loc,guid):
    RESOURCE_GROUP_NAME='RG-SAIL-prd-wus-api-web-01'
    LOCATION = loc
    vm_name = "apivm"
    IP_NAME = "IP01"+"-sail-wus-"+guid
    NIC_NAME = "NIC-"+"API"+"-sail-wus-"+guid
    IP_CONFIG_NAME = "IPCONFIG01"+"-sail-wus-"+guid
    Subnet_id = "/subscriptions/ba383264-b9d6-4dba-b71f-58b3755382d8/resourceGroups/rg-sail-wus-prd-vnet-01/providers/Microsoft.Network/virtualNetworks/vnet-sail-wus-prd-01/subnets/snet-sail-wus-prd-01"
    credential = ClientSecretCredential(tenant_id,client_id,client_secret)

# Retrieve subscription ID from environment variable.
    subscription_id = "ba383264-b9d6-4dba-b71f-58b3755382d8"

    # Get the management object for the network
    network_client = NetworkManagementClient(credential, subscription_id)
    
    # 1 - Create the Public IP address
    hub_subscription_id= "6e7f356c-6059-4799-b83a-c4744e4a7c2e"
    hub_network_client = NetworkManagementClient(credential, hub_subscription_id)
    
    poller = hub_network_client.public_ip_addresses.begin_create_or_update("rg-sail-wus-hub-001",
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
    
    api_nsg_id= "/subscriptions/ba383264-b9d6-4dba-b71f-58b3755382d8/resourceGroups/RG-SAIL-WUS-PRD-COMMON-RESOURCE/providers/Microsoft.Network/networkSecurityGroups/apiservices-wus-nsg-prd-01"

    # 2 - Create the network interface client
    poller = network_client.network_interfaces.begin_create_or_update(RESOURCE_GROUP_NAME,
        NIC_NAME, 
        {
            "location": LOCATION,
            "ip_configurations": [ {
                "name": IP_CONFIG_NAME,
                "subnet": { "id": Subnet_id }
            }],
            "network_security_group": {
            "id": api_nsg_id
        }

        }
        
    )

    nic_result = poller.result()

    print(f"Provisioned network interface client {nic_result.name}")

    # 3 - Fetching the new Private IP of the server
    poller = network_client.network_interface_ip_configurations.get(RESOURCE_GROUP_NAME,
        NIC_NAME,IP_CONFIG_NAME
    )
    pvt_ip_nic_result = poller
    pvt_ip = pvt_ip_nic_result.private_ip_address

    print(f"Private IP of the Server is {pvt_ip}")

    #Adding PIP in FW Rule
    add_pip_to_fw(guid,ip_address_result.id)


    # 4 - Create the virtual machine

    # Get the management object for virtual machines
    compute_client = ComputeManagementClient(credential, subscription_id)

    VM_NAME = vm_name+"-sail-wus-"+guid
    USERNAME = "pythonazureuser"
    PASSWORD = "ChangeM3N0w!"

    print(f"Provisioning virtual machine {VM_NAME}; this operation might take a few minutes.")

    poller = compute_client.virtual_machines.begin_create_or_update(RESOURCE_GROUP_NAME, VM_NAME,
        {
            "location": LOCATION,
            "storage_profile": {
                'image_reference': {
                'id' : '/subscriptions/ba383264-b9d6-4dba-b71f-58b3755382d8/resourceGroups/InitializerImageStorage-WUS-Rg/providers/Microsoft.Compute/images/apiservices'
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

    print(f"Provisioned API virtual machine {vm_result.name}")
    # Adding DNat rule to Firewall
    add_api_dnat_fw_rule(guid,ip_address_result.ip_address,pvt_ip,"22")
    print("------------------------------- Webfront---------------------------------")
    guid1=fetch_guid()
    status1=webft_res_creation(vm_size,loc,guid1,ip_address_result.ip_address)
    
    # inserting both ip to DB
    print("--------------------------------------------------------------------------")
    print("Insert Guid and IP to DataBase")
    insert_db_guid(guid,guid1,ip_address_result.ip_address)
    print("--------------------------------------------------------------------------")
    return [vm_id,"OK"]

#Creating WEBFRONT Plugin and its dependent resources in azure
def webft_res_creation(vm_size,loc,guid,pip):
    RESOURCE_GROUP_NAME='RG-SAIL-prd-wus-api-web-01'
    LOCATION = loc
    vm_name = "webftvm"
    NIC_NAME = "NIC-"+"WEBFT"+"-sail-wus-"+guid
    IP_CONFIG_NAME ="IPCONFIG01"+"-sail-wus-"+guid
    Subnet_id="/subscriptions/ba383264-b9d6-4dba-b71f-58b3755382d8/resourceGroups/rg-sail-wus-prd-vnet-01/providers/Microsoft.Network/virtualNetworks/vnet-sail-wus-prd-01/subnets/snet-sail-wus-prd-01"
    credential = ClientSecretCredential(tenant_id,client_id,client_secret)

# Retrieve subscription ID from environment variable.
    subscription_id = "ba383264-b9d6-4dba-b71f-58b3755382d8"

    # Get the management object for the network
    network_client = NetworkManagementClient(credential, subscription_id)
    
    webft_nsg_id="/subscriptions/ba383264-b9d6-4dba-b71f-58b3755382d8/resourceGroups/RG-SAIL-WUS-PRD-COMMON-RESOURCE/providers/Microsoft.Network/networkSecurityGroups/newwebfrontend-wus-nsg-prd-01"

    # 1 - Create the network interface client
    poller = network_client.network_interfaces.begin_create_or_update(RESOURCE_GROUP_NAME,
        NIC_NAME, 
        {
            "location": LOCATION,
            "ip_configurations": [ {
                "name": IP_CONFIG_NAME,
                "subnet": { "id": Subnet_id }
            }],
            "network_security_group": {
            "id": webft_nsg_id
        }

        }
        
    )

    nic_result = poller.result()

    print(f"Provisioned network interface client {nic_result.name}")

    # 2 - Fetching the new Private IP of the server
    poller = network_client.network_interface_ip_configurations.get(RESOURCE_GROUP_NAME,
        NIC_NAME,IP_CONFIG_NAME
    )
    pvt_ip_nic_result = poller
    pvt_ip = pvt_ip_nic_result.private_ip_address

    print(f"Private IP of the Server is {pvt_ip}")


    # 3 - Create the virtual machine

    # Get the management object for virtual machines
    compute_client = ComputeManagementClient(credential, subscription_id)

    VM_NAME = vm_name+"-sail-wus-"+guid
    USERNAME = "pythonazureuser"
    PASSWORD = "ChangeM3N0w!"

    print(f"Provisioning virtual machine {VM_NAME}; this operation might take a few minutes.")


    poller = compute_client.virtual_machines.begin_create_or_update(RESOURCE_GROUP_NAME, VM_NAME,
        {
            "location": LOCATION,
            "storage_profile": {
                'image_reference': {
                'id' : '/subscriptions/ba383264-b9d6-4dba-b71f-58b3755382d8/resourceGroups/InitializerImageStorage-WUS-Rg/providers/Microsoft.Compute/images/newwebfrontend'
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
    # Adding DNat rule to Firewall
    add_webft_dnat_fw_rule(guid,pip,pvt_ip,"443")
    return [vm_id,"OK"]

def insert_db_guid(guid,guid1,ip):
    # Intializing connection parameter to connect to the database
    config = {
    'host':'scntest.mysql.database.azure.com',
    'user':'hanuadmin@scntest',
    'password':'123@hanu123@HANU',
    'database':'sail_test_db',
    'client_flags': [mysql.connector.ClientFlag.SSL],
    'ssl_ca': '/home/sailadmin/SCN_Provisioning_Plugin/Sql_Certificate/DigiCertAssuredIDRootCA.crt (1).pem'
    #'/home/sailadmin/sail_plugin/Digi_Certificate/DigiCertAssuredIDRootCA.crt.pem'
 
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
    cursor.execute("INSERT INTO API_WEB_GUID (guid_api, guid_web, ip) VALUES (%s,%s,%s)", (guid,guid1,ip))
    print("Inserted",cursor.rowcount,"row(s) of data.")
    

    # Cleanup intialized database pointer
    conn.commit()
    cursor.close()
    conn.close()
    print("Done.")

def json_write(vm_id,TKAC,EAESK,ECB,IPSAIL):

    dictionary ={

        "VirtualMachineIdentifier": vm_id,
        "TlsKeysAndCert":TKAC,
        "EncryptedAesKey":EAESK,
        "EncryptedCompressedBinaries":ECB,
        "IpAddressOfSailPlatformServices":IPSAIL
    }

    json_string = json.dumps(dictionary)


    with open("IV.json", "w") as o:

        o.write(json_string)

def insert_db(vm_name,guid,vm_id,state):

    config = {
    'host':'scntest.mysql.database.azure.com',
    'user':'hanuadmin@scntest',
    'password':'123@hanu123@HANU',
    'database':'sail_test_db',
    'client_flags': [mysql.connector.ClientFlag.SSL],
    'ssl_ca': '/home/sailadmin/SCN_Provisioning_Plugin/Sql_Certificate/DigiCertAssuredIDRootCA.crt (1).pem'
   
    }

    # Construct connection string

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
    
    now = datetime.now()
    now=str(now) 

    # Insert some data into table
    cursor.execute("INSERT INTO platform_provisioning_plugin (vm_name, guid, resource_id, resource_state,time) VALUES (%s, %s, %s, %s, %s);", (vm_name,guid,vm_id,state,now))
    print("Inserted",cursor.rowcount,"row(s) of data.")
    

    # Cleanup
    conn.commit()
    cursor.close()
    conn.close()
    print("Done.")

def blob_fetch():
    return "xsjddwidhwwjhwoskwqjdhdhe"

    
#     plat_blob_name="platbinaryblob"
#     STORAGEACCOUNTURL = "https://sailvmimages1112.blob.core.windows.net"
#     STORAGEACCOUNTKEY = "ErDnlB2mILTBYnnYuBnw2bUeNKkW2JgYTeWCk4VR1VK+zmGtDKWhuv6AwdBQ4Fz25ndCSJtdG3Uu+AStxho3bw=="
#     CONTAINERNAME = "images"
#     BLOBNAME = "testfile.txt"

#     q=[]

#     blob_service_client_instance = BlobServiceClient(
#         account_url=STORAGEACCOUNTURL, credential=STORAGEACCOUNTKEY)

#     blob_client_instance = blob_service_client_instance.get_blob_client(
#         CONTAINERNAME, BLOBNAME, snapshot=None)
#     cst=ContainerClient( account_url= STORAGEACCOUNTURL, container_name= CONTAINERNAME,credential=STORAGEACCOUNTKEY)
#     #container_client = blob_service_client_instance(CONTAINERNAME)

#     blob_list = cst.list_blobs()
#     blob_array=[]
#     plat_blob_list=[]
#     for blob in blob_list:
#         if blob.name==plat_blob_name
#             plat_blob_list.append(blob)
#     q=[]
#     for blob in plat_blob_list:
#         q.append(str(blob.last_modified))
#     blob_download(max(q))

    

# def blob_download(file_name):

#     local_file_name=file_name
#     blob_service_client = BlobServiceClient.from_connection_string("DefaultEndpointsProtocol=https;AccountName=pkteststg1;AccountKey=vWGQatTKtuGEa+Tvv1RKAAMvIwC5oGVp6cTpaDijRsf0rXGRhReuUHtDFcqbaP063tF5j4wB+wNY+ASt/wWTOw==;EndpointSuffix=core.windows.net")
#     local_path = r"D:\\coDE\\tset"


#     download_file_path = local_path
#     blob_client = blob_service_client.get_container_client(container= "pktestcont") 
#     print("\nDownloading blob to \n\t" + download_file_path)

#     with open(download_file_path, "wb") as download_file:
#     download_file.write(blob_client.download_blob(local_file_name).readall())


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
