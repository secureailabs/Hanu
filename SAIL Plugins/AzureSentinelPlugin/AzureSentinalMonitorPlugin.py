
import requests
import json
import pandas as pd
from datetime import datetime,date
import time

from watchdog.observers import Observer

from watchdog.events import PatternMatchingEventHandler
import os

import mysql.connector
from mysql.connector import errorcode

#Initializing Service Principal
client_id="5d2ea8c7-09ea-41ce-80b6-030777fce49b"
client_secret="3PG8Q~0Jh1HU~Y3DoadZPUb5noEiJnesEJGXScLl"
tenant_id="3e74e5ef-7e6a-4cf0-8573-680ca49b64d8"

#Folder Monitoring Thread
my_observer = Observer()

#Path to monitor for json files please change this path to your monitoring path
path = "/home/sailadmin/Azure_Sentinel_Plugin/Monitor"
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
  'ssl_ca': '/home/sailadmin/Azure_Sentinel_Plugin/Sql_Certificate/DigiCertAssuredIDRootCA.crt (1).pem'
}

# Intializing pointer whenever we need to update the database

def cursor_initialize():
    #Construct connection string and intialize database pointer
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
    return (cursor,conn)

def cursor_close(cursor,conn):
    # Cleanup intialized database pointer
    conn.commit()
    cursor.close()
    conn.close()

#Dropping and recreating the new table
def drop_db(cursor):

    # query to drop table
    cursor.execute("DROP TABLE sentinal_plugin;")
    cursor.execute("DROP TABLE log_sentinal_plugin;")

    # query to recreate the table
    cursor.execute("CREATE TABLE sentinal_plugin (id serial PRIMARY KEY, place VARCHAR(80), log VARCHAR(500), timeframe VARCHAR(100))")

    cursor.execute("CREATE TABLE log_sentinal_plugin(id serial PRIMARY KEY, tenant_ids VARCHAR(500),source_system VARCHAR(500),caller_ip VARCHAR(500),category_value VARCHAR(500),correlation_id VARCHAR(500),authorization VARCHAR(500),authorization_d VARCHAR(500),claims VARCHAR(500), claims_d VARCHAR(500),level VARCHAR(500),operation_name_value VARCHAR(500),properties VARCHAR(500),properties_d VARCHAR(500),caller VARCHAR(500),event_data_id VARCHAR(500),event_sub_timestamp VARCHAR(500),http_request VARCHAR(500),operation_id VARCHAR(500),resource_group VARCHAR(500),resource_provider_value VARCHAR(500),activity_status_value VARCHAR(500),activity_sub_status_value VARCHAR(500),hierarchy VARCHAR(500),time_generated VARCHAR(500),subscription_id VARCHAR(500),operation_name VARCHAR(500),activity_status VARCHAR(500),activity_sub_status VARCHAR(500),category VARCHAR(500),resource_id VARCHAR(500),resource_provider VARCHAR(500),resource VARCHAR(500),type VARCHAR(500),_resource_id VARCHAR(500));")

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
            if (key_num(data)==1):
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

    
    trigger=data["trigger"]
    cursor,conn=cursor_initialize()

    if trigger=="yes":

        token=auth()
        #Place where the request is coming from this case API Tool
        place="clitool"

        # query to fetch all values in the table realted to clitoll/devcc comparison 

        query="select * from sentinal_plugin where place= %s"
        cursor.execute(query,(place,))
        rows = cursor.fetchall()
        print("Read",cursor.rowcount,"row(s) of data.")
        if cursor.rowcount==0:
            new_values(token)
        else:
            drop_db(cursor)
            #Fetching the last entry/last call from database
            row=rows[-1]
            q1=row[3]

            # current time
            q=datetime.utcnow()
            q = q.strftime('%m/%d/%Y, %H:%M:%S %p')

            # query to fetch the logs b/w last call and current time. Current time inclusive and last call time exclusive
            url = "https://api.loganalytics.io/v1/workspaces/26b85ef6-e144-4407-836d-284c9226b22a/query?query=AzureActivity | where TimeGenerated > datetime(" + q1 + ") and TimeGenerated <= datetime('" + q + "') "
            payload = {}
            headers = {
                'Authorization': 'Bearer ' + token,
                }
            response = requests.request("GET", url, headers=headers, data=payload)
            result = response.text
            jsondata = json.loads(result)
            values = jsondata['tables'][0]['rows']
            if len(values)==0:
                print("There are no new logs generated In b/w the last call and now ")
                return

            # Intializing columns array for logs data
            tenant_ids=[]
            source_system=[]
            caller_ip=[]
            category_value=[]
            correlation_id=[]
            authorization=[]
            authorization_d=[]
            claims=[]
            claims_d=[]
            level=[]
            operation_name_value=[]
            properties=[]
            properties_d=[]
            caller=[]
            event_data_id=[]
            event_sub_timestamp=[]
            http_request=[]
            operation_id=[]
            resource_group=[]
            resource_provider_value=[]
            activity_status_value=[]
            activity_sub_status_value=[]
            hierarchy=[]
            time_generated=[]
            subscription_id=[]
            operation_name=[]
            activity_status=[]
            activity_sub_status=[]
            category=[]
            resource_id=[]
            resource_provider=[]
            resource=[]
            type=[]
            _resource_id=[]

            # Appending the logs values one by one

            for value in values:
                tenant_ids.append(value[0])

                source_system.append(value[1])

                caller_ip.append(value[2])

                category_value.append(value[3])

                correlation_id.append(value[4])

                authorization.append(value[5])

                authorization_d.append(value[6])

                claims.append(value[7])

                claims_d.append(value[8])

                level.append(value[9])

                operation_name_value.append(value[10])

                properties.append(value[11])

                properties_d.append(value[12])

                caller.append(value[13])

                event_data_id.append(value[14])

                event_sub_timestamp.append(value[15])

                http_request.append(value[16])

                operation_id.append(value[17])

                resource_group.append(value[18])

                resource_provider_value.append(value[19])

                activity_status_value.append(value[20])

                activity_sub_status_value.append(value[21])

                hierarchy.append(value[22])

                time_generated.append(value[23])

                subscription_id.append(value[24])

                operation_name.append(value[25])

                activity_status.append(value[26])

                activity_sub_status.append(value[27])

                category.append(value[28])

                resource_id.append(value[29])

                resource_provider.append(value[30])

                resource.append(value[31])

                type.append(value[32])

                _resource_id.append(value[33])

            insert_new_status_into_db(place,operation_name_value[-1],q,cursor)
            cursor_close(cursor,conn)
            sentinal_csv_creation(tenant_ids,source_system,caller_ip,category_value,correlation_id,authorization,authorization_d,claims,claims_d,level,operation_name_value,properties,properties_d,caller,event_data_id,event_sub_timestamp,http_request,operation_id,resource_group,resource_provider_value,activity_status_value,activity_sub_status_value,hierarchy,time_generated,subscription_id,operation_name,activity_status,activity_sub_status,category,resource_id,resource_provider,resource,type,_resource_id)
            
#Authentication token for azure this token will be used by rest API's to read and write to azure

def auth():
    try:
        url = "https://login.microsoftonline.com/"+tenant_id+"/oauth2/token"

        payload='grant_type=client_credentials&client_id='+client_id+'&client_secret='+client_secret+'&resource=https://api.loganalytics.io/'
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
        print("Not able to Fetch Token")

        
# Function to insert the new logs into table         
def insert_new_status_into_db(place,log,q,cursor):

    cursor.execute("INSERT INTO sentinal_plugin (place , log , timeframe) VALUES (%s, %s, %s);", (place, log, q))
    print("Inserted",cursor.rowcount,"row(s) of data.")

#Inserting Azure Monitor Logs into Database
def insert_new_logs_into_logs_db(cursor,tenant_ids,source_system,caller_ip,category_value,correlation_id,authorization,authorization_d,claims,claims_d,level,operation_name_value,properties,properties_d,caller,event_data_id,event_sub_timestamp,http_request,operation_id,resource_group,resource_provider_value,activity_status_value,activity_sub_status_value,hierarchy,time_generated,subscription_id,operation_name,activity_status,activity_sub_status,category,resource_id,resource_provider,resource,type,_resource_id):
    lengh=len(tenant_ids)
    for j in range(0,lengh):
        cursor.execute("INSERT INTO log_sentinal_plugin(tenant_ids, source_system, caller_ip, category_value, correlation_id, authorization, authorization_d, claims ,claims_d, level, operation_name_value, properties, properties_d, caller, event_data_id, event_sub_timestamp, http_request, operation_id, resource_group, resource_provider_value, activity_status_value, activity_sub_status_value, hierarchy, time_generated, subscription_id, operation_name, activity_status, activity_sub_status, category, resource_id, resource_provider, resource, type, _resource_id) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s);",(tenant_ids[j],source_system[j],caller_ip[j],category_value[j],correlation_id[j],authorization[j],authorization_d[j],claims[j],claims_d[j],level[j],operation_name_value[j],properties[j],properties_d[j],caller[j],event_data_id[j],event_sub_timestamp[j],http_request[j],operation_id[j],resource_group[j],resource_provider_value[j],activity_status_value[j],activity_sub_status_value[j],hierarchy[j],time_generated[j],subscription_id[j],operation_name[j],activity_status[j],activity_sub_status[j],category[j],resource_id[j],resource_provider[j],resource[j],type[j],_resource_id[j]))
        print("Inserted",cursor.rowcount,"row(s) of data.")



# Function if database is empty and there is nothing to fetch for start intervals
def new_values(token):
    cursor,conn=cursor_initialize()
    #Fetching the last 15 mins data if table is empty
    url = "https://api.loganalytics.io/v1/workspaces/26b85ef6-e144-4407-836d-284c9226b22a/query?query=AzureActivity | where TimeGenerated > ago(12m)"
    print(url)
    payload = {}
    headers = {
        'Authorization': 'Bearer ' + token,
        }
    response = requests.request("GET", url, headers=headers, data=payload)
    result = response.text
    jsondata = json.loads(result)
    values = jsondata['tables'][0]['rows']
    print(values)
    if len(values)==0:
        print("No new values from portal when compared to last database entry")
        cursor_close(cursor,conn)
        return
    q=datetime.utcnow()
    q = q.strftime('%m/%d/%Y, %H:%M:%S %p')
    k=values[0]
    insert_new_status_into_db("azure",str(k[0]),q,cursor)
    tenant_ids=[]
    source_system=[]
    caller_ip=[]
    category_value=[]
    correlation_id=[]
    authorization=[]
    authorization_d=[]
    claims=[]
    claims_d=[]
    level=[]
    operation_name_value=[]
    properties=[]
    properties_d=[]
    caller=[]
    event_data_id=[]
    event_sub_timestamp=[]
    http_request=[]
    operation_id=[]
    resource_group=[]
    resource_provider_value=[]
    activity_status_value=[]
    activity_sub_status_value=[]
    hierarchy=[]
    time_generated=[]
    subscription_id=[]
    operation_name=[]
    activity_status=[]
    activity_sub_status=[]
    category=[]
    resource_id=[]
    resource_provider=[]
    resource=[]
    type=[]
    _resource_id=[]

    # Appending the logs values one by one

    for value in values:
        tenant_ids.append(value[0])

        source_system.append(value[1])

        caller_ip.append(value[2])

        category_value.append(value[3])

        correlation_id.append(value[4])

        authorization.append(value[5])

        authorization_d.append(value[6])

        claims.append(value[7])

        claims_d.append(value[8])

        level.append(value[9])

        operation_name_value.append(value[10])

        properties.append(value[11])

        properties_d.append(value[12])

        caller.append(value[13])

        event_data_id.append(value[14])

        event_sub_timestamp.append(value[15])

        http_request.append(value[16])

        operation_id.append(value[17])

        resource_group.append(value[18])

        resource_provider_value.append(value[19])

        activity_status_value.append(value[20])

        activity_sub_status_value.append(value[21])

        hierarchy.append(value[22])

        time_generated.append(value[23])

        subscription_id.append(value[24])

        operation_name.append(value[25])

        activity_status.append(value[26])

        activity_sub_status.append(value[27])

        category.append(value[28])

        resource_id.append(value[29])

        resource_provider.append(value[30])

        resource.append(value[31])

        type.append(value[32])

        _resource_id.append(value[33])
    insert_new_logs_into_logs_db(cursor,tenant_ids,source_system,caller_ip,category_value,correlation_id,authorization,authorization_d,claims,claims_d,level,operation_name_value,properties,properties_d,caller,event_data_id,event_sub_timestamp,http_request,operation_id,resource_group,resource_provider_value,activity_status_value,activity_sub_status_value,hierarchy,time_generated,subscription_id,operation_name,activity_status,activity_sub_status,category,resource_id,resource_provider,resource,type,_resource_id)
    cursor_close(cursor,conn)
    

def update_database(token):
    #Place where the request is coming from this case Azure Monitoring Cycle
    place='azure'
    cursor,conn=cursor_initialize()

    # query to fetch all values in the table realted to azure comparison

    query="select * from sentinal_plugin where place= %s"
    cursor.execute(query,(place,))
    rows = cursor.fetchall()
    print("Read",cursor.rowcount,"row(s) of data.")
    if cursor.rowcount==0:
        new_values(token)
    else:
        row=rows[-1]
        q1=row[3]

        q=datetime.utcnow()
        q = q.strftime('%m/%d/%Y, %H:%M:%S %p')
        #query to fetch the logs b/w last call and current time. Current time inclusive and last call time exclusive
        url = "https://api.loganalytics.io/v1/workspaces/26b85ef6-e144-4407-836d-284c9226b22a/query?query=AzureActivity | where TimeGenerated > datetime('" + q1 + "') and TimeGenerated <= datetime('" + q + "')"
        print(url)
        payload = {}
        headers = {
            'Authorization': 'Bearer ' + token,
            }
        response = requests.request("GET", url, headers=headers, data=payload)
        result = response.text
        jsondata = json.loads(result)
        values = jsondata['tables'][0]['rows']
        if len(values)==0:
            print("No new values from portal when compared to last database entry")
            cursor_close(cursor,conn)
            return
        k=values[0]
        insert_new_status_into_db("azure",str(k[0]),q,cursor)
        tenant_ids=[]
        source_system=[]
        caller_ip=[]
        category_value=[]
        correlation_id=[]
        authorization=[]
        authorization_d=[]
        claims=[]
        claims_d=[]
        level=[]
        operation_name_value=[]
        properties=[]
        properties_d=[]
        caller=[]
        event_data_id=[]
        event_sub_timestamp=[]
        http_request=[]
        operation_id=[]
        resource_group=[]
        resource_provider_value=[]
        activity_status_value=[]
        activity_sub_status_value=[]
        hierarchy=[]
        time_generated=[]
        subscription_id=[]
        operation_name=[]
        activity_status=[]
        activity_sub_status=[]
        category=[]
        resource_id=[]
        resource_provider=[]
        resource=[]
        type=[]
        _resource_id=[]

        # Appending the logs values one by one

        for value in values:
            tenant_ids.append(value[0])

            source_system.append(value[1])

            caller_ip.append(value[2])

            category_value.append(value[3])

            correlation_id.append(value[4])

            authorization.append(value[5])

            authorization_d.append(value[6])

            claims.append(value[7])

            claims_d.append(value[8])

            level.append(value[9])

            operation_name_value.append(value[10])

            properties.append(value[11])

            properties_d.append(value[12])

            caller.append(value[13])

            event_data_id.append(value[14])

            event_sub_timestamp.append(value[15])

            http_request.append(value[16])

            operation_id.append(value[17])

            resource_group.append(value[18])

            resource_provider_value.append(value[19])

            activity_status_value.append(value[20])

            activity_sub_status_value.append(value[21])

            hierarchy.append(value[22])

            time_generated.append(value[23])

            subscription_id.append(value[24])

            operation_name.append(value[25])

            activity_status.append(value[26])

            activity_sub_status.append(value[27])

            category.append(value[28])

            resource_id.append(value[29])

            resource_provider.append(value[30])

            resource.append(value[31])

            type.append(value[32])

            _resource_id.append(value[33])
        insert_new_logs_into_logs_db(cursor,tenant_ids,source_system,caller_ip,category_value,correlation_id,authorization,authorization_d,claims,claims_d,level,operation_name_value,properties,properties_d,caller,event_data_id,event_sub_timestamp,http_request,operation_id,resource_group,resource_provider_value,activity_status_value,activity_sub_status_value,hierarchy,time_generated,subscription_id,operation_name,activity_status,activity_sub_status,category,resource_id,resource_provider,resource,type,_resource_id)
        cursor_close(cursor,conn)

        
   

#Calling monitoring function in interval of every 30 Seconds
def start_monitoring():
    token=auth()
    update_database(token)


#Dumoing the CSV files into the local folder
def sentinal_csv_creation(tenant_ids,source_system,caller_ip,category_value,correlation_id,authorization,authorization_d,claims,claims_d,level,operation_name_value,properties,properties_d,caller,event_data_id,event_sub_timestamp,http_request,operation_id,resource_group,resource_provider_value,activity_status_value,activity_sub_status_value,hierarchy,time_generated,subscription_id,operation_name,activity_status,activity_sub_status,category,resource_id,resource_provider,resource,type,_resource_id):
    
    data ={

        "TenantId":tenant_ids,

        "SourceSystem":source_system,

        "CallerIpAddress":caller_ip,

        "CategoryValue":category_value,

        "CorrelationId":correlation_id,

        "Authorization":authorization,

        "Authorization_d":authorization_d,

        "Claims":claims,

        "Claims_d":claims_d,

        "Level":level,

        "OperationNameValue":operation_name_value,

        "Properties":properties,

        "Properties_d":properties_d,

        "Caller":caller,

        "EventDataId":event_data_id,

        "EventSubmissionTimestamp":event_sub_timestamp,

        "HTTPRequest":http_request,

        "OperationId":operation_id,

        "ResourceGroup":resource_group,

        "ResourceProviderValue":resource_provider_value,

        "ActivityStatusValue":activity_status_value,

        "ActivitySubstatusValue":activity_sub_status_value,

        "Hierarchy":hierarchy,

        "TimeGenerated":time_generated,

        "SubscriptionId":subscription_id,

        "OperationName":operation_name,

        "ActivityStatus":activity_status,

        "ActivitySubstatus":activity_sub_status,

        "Category":category,

        "ResourceId":resource_id,

        "ResourceProvider":resource_provider,

        "Resource":resource,

        "Type":type,

        "_ResourceId":_resource_id
        }
    df=pd.DataFrame(data)
    print(df)

    df.to_csv('SentinalLogs.csv',index=False)


# Main Function
if __name__ == "__main__":



    my_event_handler.on_created = on_created

    my_observer.schedule(my_event_handler, path, recursive=True)

    my_observer.start()
    q=0

    try:

        while True:
            q+=1
            # Monitor every 30 sec 
            if q%30==0:
                start_monitoring()
            # Making the value 0 again
            if q==9000000:
                q=0

            time.sleep(1)

    except KeyboardInterrupt:

        my_observer.stop()

        my_observer.join()

