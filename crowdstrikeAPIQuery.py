#This script will query the Crowdstrike API and dump a csv.
#Written By: https://github.com/TRaven/Cyber-Scripts
#Version: 1 BETA
#Version 1 working on: Add more functionality! Look at Incident and detection monitoring APIs next
#NOTE:
    # Requests and responses are formatted as JSON.
    # Requests and responses use UTC timestamps that conform to RFC 3339, such as: 2013-04-17T09:12:36-00:00
    # Auth tokens expire 30 minutes after they're created. After that time, the API responds with an auth error. When this happens, your API integration should pause, get a new auth token, then resume its normal activity.
    # You can request an auth token 10 times per minute.

import requests, json, os, csv, re, sys
from datetime import datetime

client_id = 'CROWDSTRIKE_CLIENT_ID'
client_secret = 'CROWDSTRIKE_CLIENT_SECRET'

# Ask the user for what they're looking for.
def user_input():
    options = ''
    while options not in ['1', '2', '3']:
        options = input('''Please select a Crowdstrike query:
    (1)Hostname Tracking
    (2)IP Tracking
    (3)Specify Property\n\n''')
    return options

# Main function that sets it all off.
def run_query():
    if options == '1':
        cs_host_data_evaluation(cs_get_host_by_name())
    elif options == '2':
        cs_host_data_evaluation(cs_get_host_by_ip())
    elif options == '3':
        cs_host_data_evaluation(cs_get_host_by_property())

# Lets identify the OS so we can use the appropriate file paths to store the files
def os_identification():
    if sys.platform.startswith('win') == True:
        # If Windows is identified, file will be placed int eh user's DOWNLOADS folder.
        file_path = os.getenv('USERPROFILE') + '\\Downloads\\'
    elif sys.platform.startswith('linux') == True:
        # If linux is identified, file will be placed in the user's HOME directory.
        file_path = os.getenv('HOME') + '/'   
    else:
        # If an OS can't be identified as Windows or Linux, the file can't be guaranteed to go where it's meant to go.
        # If this happened to you, you can either hard code a file_path or create another elif that identifies your OS and creates the appropriate file path!
        print("Unable to identify your OS. Script will not function as inteded.")
        sys.exit()
    return file_path

# Create the file location and name to be used with the current date and time in the front of the file in the format YYYYMMDD_HHMMSS
def name_file():
    #Generate a timestring that will be used in the filename to avoid overwriting data.
    current_date_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_suffix = {'1' : '-crowdstrikeHostSearch.csv', '2' : '-crowdstrikeIPSearch.csv', '3' : '-crowdstrikePropertySearch.csv'}
    end_file = file_path + current_date_time + file_suffix[options]
    return end_file

# Order and write the rows. Basically replace "orderee" with either "header" or "the_values" and define the order of the columns in the appropriate function.
def csv_complete(orderee, the_order):
    with open(end_file,mode='a+',newline='') as csv_file:
        # Create the CSV writer object
        csv_writer = csv.writer(csv_file)
        # Reorder the data before writing.
        try:
            orderee = [orderee[i] for i in the_order]
        except:
            pass
        # Write the rows to the CSV file
        csv_writer.writerow(orderee)

def cs_check_for_token_file():
    try:
        with open(file_path + 'crowdstrike_api_token.txt','r') as token_file:
            cs_api_auth_token = token_file.read()
    except:
        cs_api_auth_token = cs_get_api_token()
    return cs_api_auth_token

def cs_get_api_token():
    with open(file_path + 'crowdstrike_api_token.txt','w') as token_file:
        url = "https://api.crowdstrike.com/oauth2/token" 
        headers = {"Content-Type":"application/x-www-form-urlencoded", "accept":"application/json"} 
        response = requests.post(url, headers=headers, auth=(client_id, client_secret))
        tokens = json.loads(response.text)
        cs_api_auth_token = tokens['access_token']
        token_file.write(cs_api_auth_token)
    return cs_api_auth_token

'''
THIS IS THE HOST MANAGEMENT SECTION
functions down here query host management and are configured to the host management fields, queries, etc.
'''

def cs_get_device_details(aid):
    url = "https://api.crowdstrike.com/devices/entities/devices/v1"
    querystring = {'ids':aid}
    headers = {"authorization": "Bearer " + cs_api_auth_token, "accept":"application/json"} 
    response = requests.get(url, headers=headers, params=querystring)
    device_details = json.loads(response.text)
    return device_details

def cs_host_data_evaluation(hostdata):
    print('Total results: ' + str(hostdata['meta']['pagination']['total']))
    print('Limit: ' + str(hostdata['meta']['pagination']['limit']))
    if hostdata['meta']['pagination']['total'] == 0:
        print("\n\nNo Data Found")
        sys.exit()
    else:
        device_details = cs_get_device_details(hostdata['resources'])
        details = device_details['resources']
        # Sometimes not all entries will have all the columns. we can correct that here.
        column_dict = {0:'device_id',1:'cid',2:'agent_load_flags',3:'agent_local_time',4:'agent_version',5:'bios_manufacturer',6:'bios_version',7:'build_number',8:'config_id_base',9:'config_id_build',10:'config_id_platform',11:'cpu_signature',12:'external_ip',13:'mac_address',14:'instance_id',15:'service_provider',16:'service_provider_account_id',17:'hostname',18:'first_seen',19:'last_seen',20:'local_ip',21:'machine_domain',22:'major_version',23:'minor_version',24:'os_version',25:'ou',26:'platform_id',27:'platform_name',28:'policies',29:'reduced_functionality_mode',30:'device_policies',31:'groups',32:'group_hash',33:'product_type',34:'product_type_desc',35:'provision_status',36:'serial_number',37:'service_pack_major',38:'service_pack_minor',39:'pointer_size',40:'site_name',41:'status',42:'system_manufacturer',43:'system_product_name',44:'tags',45:'modified_timestamp',46:'slow_changing_modified_timestamp',47:'meta',48:'zone_group'}
        # Create a variable that will help us order the CSV columns the way we want it before we write the rows to the file.
        the_order = [17, 20, 12, 13, 18, 19, 21, 24, 34, 25, 3, 42, 43, 45, 46, 0, 1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 14, 15, 16, 22, 23, 26, 27, 28, 29, 30, 31, 32, 33, 35, 36, 37, 38, 39, 40, 41, 44, 47, 48]
        # The rows will be made into lists for manipulation later. Lets define the location of the timestamps so we can play with them.
        timestamps = [3, 18, 19, 45, 46]
        count = 0
        for detail in details:
            if count == 0:
                # Make the dictionary values into a list so we can modify the contents of the header.
                header = list(detail.keys())
                for x in column_dict:
                    try:
                        if header[x] == column_dict[x]:
                            pass
                        else:
                            header.insert(x, column_dict[x])
                    except:
                        header.insert(x, column_dict[x])
                # The times will be manipulated later on in the script. Lets make it clear that they are UTC, shall we?
                for x in timestamps:
                    header[x] = header[x] + " (UTC)"
                # Reorder the header before writing
                csv_complete(header, the_order)
                count += 1
            # Before writing the final CSV file data rows, we want to convert the ISO timestamps into a format usable by Exel.
            # First we make the dictionary values into lists so we can modify the contents
            the_values = list(detail.values())
            for x in column_dict:
                if detail.get(column_dict[x]) is None:
                    the_values.insert(x, ' ')
                else:
                    pass
            # Then we call the "column" for created, updated, and critical updated times and modify them.
            try:
                for x in timestamps:
                    the_values[x] = re.sub(r"(\d{4})\x2d(\d{2})\x2d(\d{2})T(\d{2}\x3a\d{2}\x3a\d{2}).*?Z",r"\2/\3/\1 \4",the_values[x])
            except:
                pass
            csv_complete(the_values, the_order)

def cs_get_host_by_name():
    # We need to specify that the api_auth_token variable is global so that the 401 error code portion doesn't throw an error thinking that it's a locally assigned variable.
    global cs_api_auth_token
    # Lets get the user to input some hostnames and then we can filter for em.
    cs_stringd_hostname = ''
    cs_hostname_input = input('Please enter hostname. If multiple, separate with commas: ')
    # Split the input string into a list by the commas. 
    cs_hostname_list = cs_hostname_input.split(",")
    # For the CS query, we need to have each hostname be preceeded by "hostname:" and the query needs to be in a single string.
    count = 0
    for x in cs_hostname_list:
        # At the beginning of the string, we're going to put the initial hostname:' and add the hostname from the list and strip it of any spaces. Then we add a closing quote.
        if count == 0:
            cs_stringd_hostname += "hostname:'" + x.strip() + "'"
            count += 1
        # After the first one, we will append to the string ,hostname:' followed by the next hostname in the list and closing it out with a single quote. This will repeat until the list is empty.
        else:
            cs_stringd_hostname +=  ",hostname:'" + x.strip() + "'"
    # API call.
    url = "https://api.crowdstrike.com/devices/queries/devices/v1"
    querystring = {'limit': 5000, 'filter': cs_stringd_hostname}
    headers = {"authorization": "Bearer " + cs_api_auth_token, "accept":"application/json"} 
    response = requests.get(url, headers=headers, params=querystring)
    # Assign the JSON results to a variable
    hostdata = json.loads(response.text)
    # We'll read the JSON and if we get an error 401 (Unauthorized), it'll get a new API token then rerun the function.
    try:
        if hostdata['errors'][0]['code'] == 401:
            cs_api_auth_token = cs_get_api_token()
            print('\n\nInvalid Token. New token pulled. Please retry.')
            return cs_get_host_by_name()
    except:
        pass
    return hostdata
        
def cs_get_host_by_ip():
    # We need to specify that the api_auth_token variable is global so that the 401 error code portion doesn't throw an error thinking that it's a locally assigned variable.
    global cs_api_auth_token
    # Lets get the user to input some IPs and then we can filter for em.
    cs_stringd_ip = ''
    cs_ip_input = input('Please enter IP. If multiple, separate with commas: ')
    cs_ip_list = cs_ip_input.split(",")
    count = 0
    for x in cs_ip_list:
        if count == 0:
            cs_stringd_ip += "local_ip:'" + x.strip() + "'"
            count += 1
        else:
            cs_stringd_ip +=  ",local_ip:'" + x.strip() + "'"
    # API call.
    url = "https://api.crowdstrike.com/devices/queries/devices/v1"
    querystring = {'limit': 5000, 'filter': cs_stringd_ip}
    headers = {"authorization": "Bearer " + cs_api_auth_token, "accept":"application/json"} 
    response = requests.get(url, headers=headers, params=querystring)
    # Assign the JSON results to a variable
    hostdata = json.loads(response.text)
    # We'll read the JSON and if we get an error 401 (Unauthorized), it'll get a new API token then rerun the function.
    try:
        if hostdata['errors'][0]['code'] == 401:
            cs_api_auth_token = cs_get_api_token()
            print('\n\nInvalid Token. New token pulled. Please retry.')
            return cs_get_host_by_ip()
    except:
        pass
    if hostdata['meta']['pagination']['total'] > 0:
        return hostdata
    else:
        cs_stringd_ip = ''
        count = 0
        for x in cs_ip_list:
            if count == 0:
                cs_stringd_ip += "external_ip:'" + x.strip() + "'"
                count += 1
            else:
                cs_stringd_ip +=  ",external_ip:'" + x.strip() + "'"
        # API call.
        url = "https://api.crowdstrike.com/devices/queries/devices/v1"
        querystring = {'limit': 5000, 'filter': cs_stringd_ip}
        headers = {"authorization": "Bearer " + cs_api_auth_token, "accept":"application/json"} 
        response = requests.get(url, headers=headers, params=querystring)
        # Assign the JSON results to a variable
        hostdata = json.loads(response.text)
        return hostdata

def cs_get_host_by_property():
    # We need to specify that the cs_api_auth_token variable is global so that the 401 error code portion doesn't throw an error thinking that it's a locally assigned variable.
    global cs_api_auth_token
    # Lets get the user to input some IPs and then we can filter for em.
    cs_stringd_ip = ''
    cs_property_input = input('Please enter a property to search for (i.e. product_type_desc): ')
    cs_value_input = input ('Please enter a value for the property (i.e. Domain Controller): ')
    cs_search_string = cs_property_input + ":'" + cs_value_input + "'"
    # API call.
    url = "https://api.crowdstrike.com/devices/queries/devices/v1"
    querystring = {'limit': 5000, 'filter': cs_search_string}
    headers = {"authorization": "Bearer " + cs_api_auth_token, "accept":"application/json"} 
    response = requests.get(url, headers=headers, params=querystring)
    # Assign the JSON results to a variable
    hostdata = json.loads(response.text)
    # We'll read the JSON and if we get an error 401 (Unauthorized), it'll get a new API token then rerun the function.
    try:
        if hostdata['errors'][0]['code'] == 401:
            cs_api_auth_token = cs_get_api_token()
            print('\n\nInvalid Token. New token pulled. Please retry.')
            return cs_get_host_by_property()
    except:
        pass
    return hostdata

'''
END HOST MANAGEMENT SECTION
'''

file_path = os_identification()
cs_api_auth_token = cs_check_for_token_file()
options = user_input()
end_file = name_file()

run_query()
print(end_file + " created.")