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
import requests

from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient, __version__
import json

from random import *

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
path = "/home/sailadmin/SCN_Provisioning_Plugin/Monitor"
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
    guid=fetch_guid()
    vm_name=data['vm_name']
    rg_name=data['rg_name']
    nsg_name=data['nsg_name']
    vnet_name=data['vnet_name']
    vm_size=data['Request']['VirtualMachineType']
    loc=data['Request']['Region'] 
    insert_db(vm_name,guid,guid,"Provisioning")
    status=scn_res_creation(rg_name,vnet_name,nsg_name,vm_name,vm_size,loc,guid)
    vm_status=fetch_vm_status_from_azure(status[0],token)
    vm_name=status[0].split('/')
    vm_name=vm_name[-1]
    if status[1]!="OK":
        now = datetime.now()
        now=str(now)
        insert_db(vm_name,guid,guid,"Not Provisioned")
    insert_db(vm_name,guid,status[0],vm_status)
    json_write(status[0],ROI,DOOI,DCI,DI,TKAC,EAESK,ECB,RORP,DOORP,AORP,SORP,EADEK,IPSAIL)


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
        print("Public Ip Added Successfully To Azure Firewall")
    except error:
        print(error)


# Adding Newly created SCN Dnat rule to firewall policy
def add_scn_dnat_fw_rule(guid,p_ip,pvt_ip):
    token=auth()
    y= {
                    "ruleType": "NatRule",
                    "name": guid,
                    "translatedAddress": pvt_ip,
                    "translatedPort": "22",
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
                        "22"
                    ]
                }
    try:
        url = "https://management.azure.com//subscriptions/6e7f356c-6059-4799-b83a-c4744e4a7c2e/resourceGroups/rg-sail-wus-hub-001/providers/Microsoft.Network/firewallPolicies/afwpol-sail-wus-001/ruleCollectionGroups/SCNRuleCollectionGroup?api-version=2022-01-01"
        headers = {
            'Authorization': 'Bearer ' + token,
            'Accept' : 'application/json', 
            'Content-Type' : 'application/json'
            }
        response = requests.request("GET", url, headers=headers)
        result = response.text
        jsondata = json.loads(result)
        jsondata["properties"]["ruleCollections"][0]["rules"].append(y)
        with open('add_scnnatrule_to_hubfw.json', 'w+') as json_file:
            json.dump(jsondata, json_file) 
        json_file.close()
        with open('add_scnnatrule_to_hubfw.json', 'r+') as json_file:
            data = json.load(json_file)
        json_file.close()
    except error:
        print(error)
    try:
        url = "https://management.azure.com//subscriptions/6e7f356c-6059-4799-b83a-c4744e4a7c2e/resourceGroups/rg-sail-wus-hub-001/providers/Microsoft.Network/firewallPolicies/afwpol-sail-wus-001/ruleCollectionGroups/SCNRuleCollectionGroup?api-version=2022-01-01"
        headers = {
            'Authorization': 'Bearer ' + token,
            'Accept' : 'application/json', 
            'Content-Type' : 'application/json'
            }
        response = requests.request("PUT", url, headers=headers, data=json.dumps(data))
        result = response.text
        jsondata = json.loads(result)
        print("Added Dnat Rule for SCN Successfully")
    except error:
        print(error)
    
#Fetching Unique ID for every new SCN Provisioned
def fetch_guid():
    import uuid 
    guid=uuid.uuid4()
    return str(guid)

# To get the provisioning status of new API Plugin from azure 
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

# Creating SCN Plugin and dependent resources in azure 

def scn_res_creation(rg_name,vnet_name,nsg_name,vm_name,vm_size,loc,guid):
    with open('Sub_Parameters.json', 'r+') as json_file:
            variable = json.load(json_file)
    json_file.close()
        
    credential = ClientSecretCredential(tenant_id,client_id,client_secret)

# Retrieve subscription ID from environment variable.
    subscription_id = variable["subscription_id"]


    # 1 - create a resource group

    # Get the management object for resources, this uses the credentials from the CLI login.
    resource_client = ResourceManagementClient(credential, subscription_id)

    # Set constants we need in multiple places.  You can change these values however you want.
    rg_name=rg_name+"-sail-wus-"+guid
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
    VNET_NAME = vnet_name+"-sail-wus-"+guid
    SUBNET_NAME = vnet_name +"-SNET01"
    IP_NAME = "IP01"+"-sail-wus-"+guid
    IP_CONFIG_NAME = "IPCONFIG01"+"-sail-wus-"+guid
    NIC_NAME = "NIC-"+"SCN"+"-sail-wus-"+guid

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
                "address_prefixes": ["172.23.0.0/29"]
            }
        }
    )

    vnet_result = poller.result()
    print(f"Provisioned virtual network {vnet_result.name} with address prefixes {vnet_result.address_space.address_prefixes}")



    # 3 - Create the subnet
    subres3 = SubResource(id="/subscriptions/ba383264-b9d6-4dba-b71f-58b3755382d8/resourceGroups/rg-sail-wus-prd-vnet-01/providers/Microsoft.Network/routeTables/rt-sail-wus-prd-01")
    SUBNET_DATA=Subnet(address_prefix= "172.23.0.0/29", route_table=subres3)
    poller = network_client.subnets.begin_create_or_update(RESOURCE_GROUP_NAME, 
        VNET_NAME, SUBNET_NAME,SUBNET_DATA
    )
    subnet_result = poller.result()

    print(f"Provisioned virtual subnet {subnet_result.name} with address prefix {subnet_result.address_prefix}")


    # 3.1 - Peering Virtual Networks Plugin VNET to SCN VNET
    peer_vnet_name=vnet_name+"-sail-wus"
    prd_subscription_id= variable["prd_subscription_id"]
    prd_network_client = NetworkManagementClient(credential, prd_subscription_id)
    prd_resource_client = ResourceManagementClient(credential, prd_subscription_id)
    resource_client.providers.register('Microsoft.Network')
    prd_resource_client.providers.register('Microsoft.Network')

    res1 = resource_client.resources.get(RESOURCE_GROUP_NAME, "Microsoft.Network", "", "virtualNetworks", VNET_NAME, "2022-01-01")
    res2 = prd_resource_client.resources.get("rg-sail-wus-prd-vnet-01", "Microsoft.Network", "", "virtualNetworks", "vnet-sail-wus-prd-01", "2022-01-01")

    subres1 = SubResource(id=res1.id)
    subres2 = SubResource(id=res2.id)

    peering_params1 =  VirtualNetworkPeering(allow_virtual_network_access=True, allow_forwarded_traffic=True ,allow_gateway_transit=False,remote_virtual_network=subres1)
    peering_params2 =  VirtualNetworkPeering(allow_virtual_network_access=True, allow_forwarded_traffic=True, use_remote_gateways=False,remote_virtual_network=subres2)

    peer_name_1="vnet-sail-wus-prd-01-To-"+peer_vnet_name
    peer_name_2=peer_vnet_name+"-To-vnet-sail-wus-prd-01"
    poller2 = network_client.virtual_network_peerings.begin_create_or_update(RESOURCE_GROUP_NAME, VNET_NAME, peer_name_2, peering_params2)
    poller1 = prd_network_client.virtual_network_peerings.begin_create_or_update("rg-sail-wus-prd-vnet-01", "vnet-sail-wus-prd-01", peer_name_1, peering_params1)

    peer_result1=poller1.result()
    peer_result2=poller2.result()
    

    print(f"Created virtual network peering b/w Plugin VNET and SCN VNET with names {peer_result1.name} and {peer_result2.name}")

    # 3.2 - Peering Virtual Networks SAIL Hub and SCN VNET
    peer_vnet_name=vnet_name+"-sail-wus"
    hub_subscription_id= variable["hub_subscription_id"]
    hub_network_client = NetworkManagementClient(credential, hub_subscription_id)
    hub_resource_client = ResourceManagementClient(credential, hub_subscription_id)
    resource_client.providers.register('Microsoft.Network')
    hub_resource_client.providers.register('Microsoft.Network')

    res1 = resource_client.resources.get(RESOURCE_GROUP_NAME, "Microsoft.Network", "", "virtualNetworks", VNET_NAME, "2022-01-01")
    res2 = hub_resource_client.resources.get("rg-sail-wus-hub-001", "Microsoft.Network", "", "virtualNetworks", "vnet-sail-wus-hub-001", "2022-01-01")

    subres1 = SubResource(id=res1.id)
    subres2 = SubResource(id=res2.id)

    peering_params1 =  VirtualNetworkPeering(allow_virtual_network_access=True, allow_forwarded_traffic=True ,allow_gateway_transit=True,remote_virtual_network=subres1)
    peering_params2 =  VirtualNetworkPeering(allow_virtual_network_access=True, allow_forwarded_traffic=True, use_remote_gateways=True,remote_virtual_network=subres2)

    peer_name_1="vnet-sail-wus-hub-001-To-"+peer_vnet_name
    peer_name_2=peer_vnet_name+"-To-vnet-sail-wus-hub-001"
    poller2 = network_client.virtual_network_peerings.begin_create_or_update(RESOURCE_GROUP_NAME, VNET_NAME, peer_name_2, peering_params2)
    poller1 = hub_network_client.virtual_network_peerings.begin_create_or_update("rg-sail-wus-hub-001", "vnet-sail-wus-hub-001", peer_name_1, peering_params1)

    peer_result1=poller1.result()
    peer_result2=poller2.result()
    

    print(f"Created virtual network peering b/w Hub and SCN VNET with names {peer_result1.name} and {peer_result2.name}")

    hub_network_client = NetworkManagementClient(credential, hub_subscription_id)
    # 4 - Create the IP address
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

    print(f"Provisioned public IP address {ip_address_result.name} with address {ip_address_result.ip_address} ")
    
    #Adding Public IP for SCN in Firewall.
    add_pip_to_fw(guid,ip_address_result.id)

    # 5 - Creating the Network Security Group with default values
    nsg_name="NSG"+"-"+nsg_name+"-sail-wus-"+guid
    
    nsg_params = NetworkSecurityGroup(id=nsg_name,location=LOCATION)
    nsg = network_client.network_security_groups.begin_create_or_update(RESOURCE_GROUP_NAME, nsg_name, parameters=nsg_params)
    nsg=nsg.result()
    print(f"Provisioned Network Security Group with name {nsg.name}")

    # 5.1 - Create the network interface client
    poller = network_client.network_interfaces.begin_create_or_update(RESOURCE_GROUP_NAME,
        NIC_NAME, 
        {
            "location": LOCATION,
            "ip_configurations": [ {
                "name": IP_CONFIG_NAME,
                "subnet": { "id": subnet_result.id }
            }],
            "network_security_group": {
            "id": nsg.id
        }

        }
        
    )

    nic_result = poller.result()
    print(f"Provisioned network interface client {nic_result.name}")

    # 5.2 -Fetching the new Private IP of the server
    poller = network_client.network_interface_ip_configurations.get(RESOURCE_GROUP_NAME,
        NIC_NAME,IP_CONFIG_NAME
    )
    pvt_ip_nic_result = poller
    pvt_ip = pvt_ip_nic_result.private_ip_address

    print(f"Private IP of the Server is {pvt_ip}")    

    # 6 - Create the virtual machine

    # Get the management object for virtual machines
    compute_client = ComputeManagementClient(credential, subscription_id)

    VM_NAME = vm_name+"-sail-wus-"+guid
    USERNAME = variable["username"]
    PASSWORD = variable["password"]

    print(f"Provisioning virtual machine {VM_NAME}; this operation might take a few minutes.")

    # Create the VM (Ubuntu 18.04 VM)
    # on a Standard DS1 v2 plan with a public IP address and a default virtual network/subnet.

    poller = compute_client.virtual_machines.begin_create_or_update(RESOURCE_GROUP_NAME, VM_NAME,
        {
            "location": LOCATION,
            "storage_profile": {
                'image_reference': {
                'id' : variable["image_id"]
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

    #Adding DNAT rule for SCN in Firewall
    add_scn_dnat_fw_rule(guid,ip_address_result.ip_address,pvt_ip)
    # Adding ip to DB
    print("--------------------------------------------------------------------------")
    print("Insert Guid and IP to DataBase")
    insert_db_guid(guid,ip_address_result.ip_address)
    print("--------------------------------------------------------------------------")
    return [vm_id,"OK"]



# Inserting new status in the database
def insert_db(vm_name,guid,vm_id,state):
    # Intializing connection parameter to connect to the database
    config = {
    'host':'scntest.mysql.database.azure.com',
    'user':'hanuadmin@scntest',
    'password':'123@hanu123@HANU',
    'database':'sail_test_db',
    'client_flags': [mysql.connector.ClientFlag.SSL],
    'ssl_ca': '/home/sailadmin/SCN_Provisioning_Plugin/Sql_Certificate/DigiCertAssuredIDRootCA.crt (1).pem'

 
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
    now = datetime.now()
    now=str(now) 
    # Inserting data into table
    cursor.execute("INSERT INTO scn_provisioning_plugin (vm_name, guid, resource_id,resource_state,time) VALUES (%s, %s, %s,%s, %s);", (vm_name,guid,vm_id,state,now))
    print("Inserted",cursor.rowcount,"row(s) of data.")
    

    # Cleanup intialized database pointer
    conn.commit()
    cursor.close()
    conn.close()
    print("Done.")

# Inserting guid and ip in the database
def insert_db_guid(guid,ip):
    # Intializing connection parameter to connect to the database
    config = {
    'host':'scntest.mysql.database.azure.com',
    'user':'hanuadmin@scntest',
    'password':'123@hanu123@HANU',
    'database':'sail_test_db',
    'client_flags': [mysql.connector.ClientFlag.SSL],
    'ssl_ca': '/home/sailadmin/SCN_Provisioning_Plugin/Sql_Certificate/DigiCertAssuredIDRootCA.crt (1).pem'

 
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
    cursor.execute("INSERT INTO SCN_GUID (guid, ip) VALUES (%s,%s)", (guid,ip))
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

# Fetching the images from azure blob
def blob_fetch():
    return "sshddejdjeigtdfvxdfdtrscsbkdhehdj"
    """
    scn_blob_name="scnbinaryblob"
    STORAGEACCOUNTURL = "https://sailvmimages1112.blob.core.windows.net"
    STORAGEACCOUNTKEY = "ErDnlB2mILTBYnnYuBnw2bUeNKkW2JgYTeWCk4VR1VK+zmGtDKWhuv6AwdBQ4Fz25ndCSJtdG3Uu+AStxho3bw=="
    CONTAINERNAME = "images"
    BLOBNAME = "testfile.txt"

    q=[]

    blob_service_client_instance = BlobServiceClient(
        account_url=STORAGEACCOUNTURL, credential=STORAGEACCOUNTKEY)

    blob_client_instance = blob_service_client_instance.get_blob_client(
        CONTAINERNAME, BLOBNAME, snapshot=None)
    cst=ContainerClient( account_url= STORAGEACCOUNTURL, container_name= CONTAINERNAME,credential=STORAGEACCOUNTKEY)
    #container_client = blob_service_client_instance(CONTAINERNAME)

    blob_list = cst.list_blobs()
    scn_blob_list=[]
    for blob in blob_list:
        if blob.name==scn_blob_name
            scn_blob_list.append(blob)
    q=[]
    for blob in scn_blob_list:
        q.append(str(blob.last_modified))
    
    for blob in blob_list:
        q.append(str(blob.last_modified))
    blob_download(max(q))
        

# Downloading the blob file from azure conatainer
def blob_download(file_name):
    
    local_file_name=file_name
    blob_service_client = BlobServiceClient.from_connection_string("DefaultEndpointsProtocol=https;AccountName=pkteststg1;AccountKey=vWGQatTKtuGEa+Tvv1RKAAMvIwC5oGVp6cTpaDijRsf0rXGRhReuUHtDFcqbaP063tF5j4wB+wNY+ASt/wWTOw==;EndpointSuffix=core.windows.net")
    local_path = r"D:\\coDE\\tset"


    download_file_path = local_path
    blob_client = blob_service_client.get_container_client(container= "pktestcont") 
    print("\nDownloading blob to \n\t" + download_file_path)

    with open(download_file_path, "wb") as download_file:
    download_file.write(blob_client.download_blob(local_file_name).readall())
    """

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
