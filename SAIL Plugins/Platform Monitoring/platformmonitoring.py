
from watchdog.observers import Observer

from watchdog.events import PatternMatchingEventHandler

import mysql.connector
from mysql.connector import errorcode

import requests
import json
#import pandas as pd
from datetime import datetime,date
import time
#import threading
#import win32com.client
import os

#Initializing Service Principal
client_id="a547fa4d-296c-4c1c-ab90-c5010bd1ae5f"
client_secret="Ne28Q~cXnQB_FVv4~3Wy-VgzfAVPOW3NVI3GTbkI"
tenant_id="3e74e5ef-7e6a-4cf0-8573-680ca49b64d8"

#Folder Monitoring Thread
my_observer = Observer()

#Path to monitor for json files please change this path to your monitoring path

path = "C:\\Users\PriyanshuKumar\OneDrive - HANU SOFTWARE SOLUTIONS INDIA PRIVATE LIMITED\MY Codes\Python Secure AI\PLATFORM MONITORING\Monitor"

patterns = ["*.json"]

ignore_patterns = None

ignore_directories = False

case_sensitive = True

my_event_handler = PatternMatchingEventHandler(patterns, ignore_patterns, ignore_directories, case_sensitive)


# Intializing connection parameter to connect to the database
config = {
  'host':'scntest.mysql.database.azure.com',
  'user':'hanuadmin@scntest',
  'password':'123@hanu123@HANU',
  'database':'sail_test_db',
  'client_flags': [mysql.connector.ClientFlag.SSL],
  'ssl_ca': 'C:\\Users\PriyanshuKumar\OneDrive - HANU SOFTWARE SOLUTIONS INDIA PRIVATE LIMITED\MY Codes\Python Secure AI\DigiCertAssuredIDRootCA.crt.pem'
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

#Dependent function for monitoring 

def key_num(d):

   return sum(not isinstance(b, dict) or 1 + key_num(b) for b in d.values())

# Monitoring Function'

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
            if (key_num(data)==2):
                f1=False
                os.remove(lock_file)
            f.close()
        except:
            pass
    if(os.path.exists(lock_file)):
        pass
    else:
        print(".lock file removed")
    
    with open(event.src_path) as jsondata:
        data=json.load(jsondata)

    vm_id=data["vm_id"]
    vm_status=data["vm_status"]
    fetch_vm_status_for_API(vm_id,vm_status)

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

# Function to fetch all VM's in that subscription
def list_of_all_VM(token):
    #Fetch all VM's in that subscription change subscription id in the query
    url = "https://management.azure.com/subscriptions/b7a46052-b7b1-433e-9147-56efbfe28ac5/providers/Microsoft.Compute/virtualMachines?api-version=2022-03-01"
    payload = {}
    headers = {
        'Authorization': 'Bearer ' + token,
        }
    response = requests.request("GET", url, headers=headers, data=payload)
    result = response.text
    jsondata = json.loads(result)
    values = jsondata["value"]
    for j in values:
        fetch_vm_status_for_azure(j['id'],token)


# Fetching the current status of the VM
def fetch_vm_status_for_azure(ID,token):
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
    compare_azure_with_db(ID,now_status)

#Comparing data b/w azure and API call from DEVCC
def fetch_vm_status_for_API(ID,status):
    token=auth()
    try:
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
    except:
        print("There is NO such VM")
    print(now_status)
    if status != now_status:
        print("API Data Mismatch")
        insert_new_status_into_db(ID,now_status)
        title=("The API reported the correct Mismatch!!\n Updated the Database record")
        #alert_mail(title)

# Comparing data with azure and database last entry
def compare_azure_with_db(vm_id,new_vm_status):
    try:
        
        query="select * from platform_provisioning_plugin where resourceid= %s"
        cursor.execute(query,(vm_id,))
        rows = cursor.fetchall()
        print("Read",cursor.rowcount,"row(s) of data.")
        row=rows[-1]
    except:
        print("There is no such VM registered in the database")
        return
    print(row[4])
    past_vm_status=row[4]
    if new_vm_status!=past_vm_status:
        print("Database Not Matched")
        insert_new_status_into_db(vm_id,new_vm_status)
        title=("There is match in the Database with Azure!!\n Updated the Database record")
        #alert_mail(title)

# Inserting new status in database
def insert_new_status_into_db(ID,new_status):
    name_vm=ID.split('/')
    name_vm=name_vm[-1]
    time_now=datetime.now()

    # Inserting into table
    cursor.execute("INSERT INTO platform_provisioning_plugin (vm_name , resource_id , resoure_state , time) VALUES (%s, %s, %s, %s);", (name_vm, ID, new_status, time_now))
    print("Inserted",cursor.rowcount,"row(s) of data.")


# Generate Email to a specific action, needs local desktop outlook access

def alert_mail(title):
    pass

"""
    outlook = win32com.client.Dispatch('outlook.application')

    mail = outlook.CreateItem(0)

    mail.To = 'engineerpriyanshu7@gmail.com'

    mail.Subject = 'SCN Plugin Alert'

    #mail.HTMLBody = '<h3>This is HTML Body</h3>'

    mail.Body = title

    mail.Send()
"""
# Monitoring every 30 sec b/w azure and database
def start_monitoring():
    token=auth()
    list_of_all_VM(token)


if __name__ == "__main__":



    my_event_handler.on_created = on_created

    my_observer.schedule(my_event_handler, path, recursive=True)

    my_observer.start()
    q=0

    try:

        while True:
            # Monitor every 30 sec 
            q+=1
            if q%10==0:
                start_monitoring()
            
            if q==8000000:
                q=0

            time.sleep(1)

    except KeyboardInterrupt:

        my_observer.stop()

        my_observer.join()
    



