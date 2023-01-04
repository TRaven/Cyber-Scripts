#This script will query iceberg API and dump a csv.
#Written By: https://github.com/TRaven/Cyber-Scripts
#Version: 6 BETA
#V6 Working on: Cleanup.
#NOTE:
    # Requests and responses are formatted as JSON.
    # Requests and responses use UTC timestamps that conform to RFC 3339, such as: 2013-04-17T09:12:36-00:00

import requests, os, json, csv, re, sys
from datetime import datetime

# Generate an API token for the IBToken field from Settings > Profile Settings > Token. Keep it written somewhere because it wont display it again. 
api_token = "GIGAMON_API_TOKEN"
# Account UUID
account_uuid = "GIGAMON_ACCOUNT_UUID"

# Main function that takes the selection and directs it to the appropriate function.
def run_query():
    if options == '1':
        dhcp_tracking()
    elif options == '2':
        pdns_tracking()
    elif options == '3':
        rule_list_query()
    elif options == '4':
        detection_list_query()
    elif options == '5':
        list_detection_events()


# Ask the user for what they're looking for.
def user_input():
    options = ''
    while options not in ['1', '2', '3', '4', '5']:
        options = input('''Please select an Icebrg query:
    (1)DHCP Tracking
    (2)Passive DNS (PDNS) Tracking
    (3)Rule list
    (4)Detection List
    (5)List Events for Detection. WARNING: Results may vary.
    
    Selection: ''')
    return options

# Lets identify the OS so we can use the appropriate file paths to store the files
def os_identification():
    if sys.platform.startswith('win') == True:
        # If Windows is identified, file will be placed int eh user's DOWNLOADS folder.
        file_path = os.getenv('USERPROFILE') + '\\Downloads\\'
    elif sys.platform.startswith('linux') == True:
        # If linux is identified, file will be placed in the user's HOME directory.
        file_path = os.getenv('HOME') + '/'   
    else:
        # If an OS can't be identified as Windows or Linux, the file can't be guaranteed to go where it's meant to go
        # If this happened to you, you can either hard code a file_path or create another elif that identifies your OS and creates the appropriate file path!
        print("Unable to identify your OS. Script will not function as inteded.")
        sys.exit()
    return file_path

# Create the file location and name to be used with the current date and time in the front of the file in the format YYYYMMDD_HHMMSS
def name_file():
    #Generate a timestring that will be used in the filename to avoid overwriting data.
    current_date_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_suffix = {'1' : '-DHCPTrackingData.csv', '2' : '-PDNSTrackingData.csv', '3' : '-icebrgRuleList.csv', '4' : '-icebrgDetectionList.csv', '5' : '-icebrgEventList.csv'}
    end_file = file_path + current_date_time + file_suffix[options]
    return end_file

# Order and write the rows. Basically replace "orderee" with either "header" or "the_values" and that's it.
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

# API call for Rule list.
def rule_list_query():
    # The following follows the query as defined in https://portal.icebrg.io/help/api/detection-api.
    url = "https://detections.icebrg.io/v1/rules" 
    querystring = {"account_uuid" : account_uuid, "limit":"1000"} 
    headers = {"cookie":"IBToken=" + api_token,"Content-Type": "application/json"} 
    response = requests.request("GET", url, headers=headers, params=querystring)
    #put the results in a variable
    json_results = json.loads(response.text)
    # The JSON is a dictionary. Call the rules key in the dictionary and assign it to a variable. 
    the_rules = json_results['rules']
    # Create a variable that will help us order the CSV columns the way we want it before we write the rows to the file.
    the_order = [4, 5, 8, 9, 11, 13, 15, 16, 7, 6, 22, 0, 1, 2, 3, 10, 12, 14, 17, 18, 19, 20, 21, 23]
    # The rows will be made into lists for manipulation later. Lets define the location of the timestamps so we can play with them.
    timestamps = [13, 15, 16]
    # Counter variable used for writing header row to the CSV file
    count = 0
    for rule in the_rules:
        if count == 0:
            # Make the dictionary values into a list so we can modify the contents of the header.
            header = list(rule.keys())
            # The times will be manipulated later on in the script. Lets make it clear that they are UTC, shall we?
            for x in timestamps:
                header[x] = header[x] + " (UTC)"
            # Reorder the header before writing
            csv_complete(header, the_order)
            count += 1
        # Before writing the final CSV file data rows, we want to convert the ISO timestamps into a format usable by Exel.
        # First we make the dictionary values into lists so we can modify the contents
        the_values = list(rule.values())
        # Then we call the "column" for created, updated, and critical updated times and modify them.
        for x in timestamps:
            the_values[x] = re.sub(r"(\d{4})\x2d(\d{2})\x2d(\d{2})T(\d{2}\x3a\d{2}\x3a\d{2})\x2e\d{6}Z",r"\2/\3/\1 \4",the_values[x])
        csv_complete(the_values, the_order)

# API call for detection list
def detection_list_query():
    # The following follows the query as defined in https://portal.icebrg.io/help/api/detection-api.
    url = "https://detections.icebrg.io/v1/detections" 
    querystring = {"account_uuid":account_uuid, "limit":"1000", "sort_by":"last_seen"} 
    headers = {"cookie":"IBToken=" + api_token,"Content-Type": "application/json"} 
    response = requests.request("GET", url, headers=headers, params=querystring)
    # We are going to add some more columns to each detection with some more information from a ruie UUID query. Lets define those columns here.
    # Note, if you add more entries here, you will need to add more values to the variable the_order or your added columns will not be on the CSV.
    add_to_detection = ['name', 'category', 'severity', 'confidence', 'description', 'query_signature']
    # Create a variable that will help us order the CSV columns the way we want it before we write the rows to the file.
    the_order = [0, 20, 21, 24, 25, 26, 27, 2, 18, 19, 16, 17, 28, 29, 3, 5, 13, 12, 14, 15, 8, 7, 11, 6, 9, 10, 1, 4, 22, 23]
    # The rows will be made into lists for manipulation later. Lets define the location of the timestamps in those lists so we can play with them.
    timestamps = [20, 21, 22, 23]
    #put the results in a variable
    json_results = json.loads(response.text)
    # The JSON is a dictionary. Call the rules key in the dictionary and assign it to a variable. 
    the_detections = json_results['detections']
    local_rule_db = {}
    # Counter variable used for writing header row to the CSV file
    count = 0
    for detection in the_detections:
        # We need to define extra empty keys for the detections dictionary so we can add data from the rule lookup.
        for x in add_to_detection:
            detection[x] = ''
        # This first IF will define and write the header of the CSV file
        if count == 0:
            # Make the dictionary values into a list so we can modify the contents of the header.
            header = list(detection.keys())
            # The times will be manipulated later on in the script. Lets make it clear that they are UTC, shall we?
            for x in timestamps:
                header[x] = header[x] + " (UTC)"
            csv_complete(header, the_order)
            count += 1
        # When we query for a specific rule's information in the ELSE, we will be adding it to a temp local DB in memory so we don't have to query the server for every line of detection, we can look locally and find the details we need and add them.
        if detection['rule_uuid'] in local_rule_db.keys():
            # Here we actually define the empty keys we created earlier in the FOR loop using the entry from the local_rule_db variable dictionary
            for x in add_to_detection:
                detection[x] = local_rule_db[detection['rule_uuid']][x]
        # This else is the alternative for the if function above. If the rule_uuid isn't a key in the local_rule_db variable, then this logic will run
        else:
            # The following follows the query as defined in https://portal.icebrg.io/help/api/detection-api.
            # We will take the detection rule_uuid and search for it.
            rule_search_url = "https://detections.icebrg.io/v1/rules/" + detection['rule_uuid']
            rule_search_response = requests.request("GET", rule_search_url, headers=headers)
            #put the results in a variable
            rule_search_json_results = json.loads(rule_search_response.text)
            # The JSON is a dictionary. Call the rules key in the dictionary and assign it to a variable.
            rule_search_result = rule_search_json_results['rule']
            # Lets define an empty dictionary for each UUID
            local_rule_db[detection['rule_uuid']] = {}
            # Fill out the empty keys we made earlier and then add those to the local DB           
            for x in add_to_detection:
                detection[x] = rule_search_result[x]
                # We will also assign those keys to the local_rule_db variable dictionary so we can call them if there are duplicates down the line
                local_rule_db[detection['rule_uuid']][x] = rule_search_result[x]
        # Before writing the final CSV file data rows, we want to convert the ISO timestamps into a format usable by Exel.
        # First we make the dictionary values into lists so we can modify the contents
        the_values = list(detection.values())
        # Then we call the "column" for first_seen, last_seen, created, and updated times and modify them.
        for x in timestamps:
            the_values[x] = re.sub(r"(\d{4})\x2d(\d{2})\x2d(\d{2})T(\d{2}\x3a\d{2}\x3a\d{2})\x2e\d{6}Z",r"\2/\3/\1 \4",the_values[x])
        csv_complete(the_values, the_order)

def dhcp_tracking():
    entity_selection = ''
    # Counter variable used for writing header row to the CSV file
    count = 0
    while entity_selection not in ['1', '2', '3']:
        entity_selection = input('''Please select an Entity Type:
    (1)IP Address
    (2)MAC Address
    (3)Hostname\n\n''')
    entity_input = input('Please enter entity. If multiple, separate with commas: ')
    entity_list = entity_input.split(",")
    
    for entity in entity_list:
        entity = entity.strip()
        if entity_selection == '1':
            url = "https://entity.icebrg.io/v2/entity/tracking/ip/" + entity
        elif entity_selection == '2':
            url = "https://entity.icebrg.io/v2/entity/tracking/mac/" + entity
        elif entity_selection == '3':
            url = "https://entity.icebrg.io/v2/entity/tracking/hostname/" + entity
        querystring = {"account_uuid" : account_uuid} 
        headers = {"cookie":"IBToken=" + api_token,"Content-Type": "application/json"} 
        response = requests.request("GET", url, headers=headers, params=querystring)
        # Create a variable that will help us order the CSV columns the way we want it before we write the rows to the file.
        the_order = [3, 2, 1, 4, 5, 0]
        # The rows will be made into lists for manipulation later. Lets define the location of the timestamps in those lists so we can play with them.
        timestamps = [4, 5]
        #put the results in a variable
        json_results = json.loads(response.text)
        # The JSON is a dictionary. Call the rules key in the dictionary and assign it to a variable. 
        the_dhcp = json_results['entity_tracking_response']['dhcp_mac_ip_intervals']
        if the_dhcp == []:
            print("\n\nNo results found for " + entity)
        else:
            print("\nResult found for " + entity + "\n")
            for hit in the_dhcp:
                if count == 0:
                    # Make the dictionary values into a list so we can modify the contents of the header.
                    header = list(hit.keys())
                    # The times will be manipulated later on in the script. Lets make it clear that they are UTC, shall we?
                    for x in timestamps:
                        header[x] = header[x] + " (UTC)"
                    # Writing header row of the CSV file
                    csv_complete(header, the_order)
                    count += 1
                # Before writing the final CSV file data rows, we want to convert the ISO timestamps into a format usable by Exel.
                # First we make the dictionary values into lists so we can modify the contents
                the_values = list(hit.values())
                # Then we call the "column" for interval_start and interval_end times and modify them.
                # NOTE: interval_end may be blank which would throw an error and kill the script if we didn't put it in a try/except loop.
                try:
                    for x in timestamps:
                        the_values[x] = re.sub(r"(\d{4})\x2d(\d{2})\x2d(\d{2})T(\d{2}\x3a\d{2}\x3a\d{2})\x2e\d{6}Z",r"\2/\3/\1 \4",the_values[x])
                except:
                    pass
                # Write the data rows of the CSV file
                csv_complete(the_values, the_order)

def pdns_tracking():
    # Counter variable used for writing header row to the CSV file
    count = 0
    pdns_input = ''
    pdns_input = input('Please input IP or Domain. Separate multiples with a comma: ')
    pdns_entity = pdns_input.split(",")
    
    for entity in pdns_entity:
        entity = entity.strip()
        # The following follows the query as defined in https://portal.icebrg.io/help/api/entity-api
        url = "https://entity.icebrg.io/v1/entity/" + entity + "/pdns" 
        querystring = {"account_uuid" : account_uuid} 
        headers = {"Content-Type": "application/json","cookie":"IBToken=" + api_token} 
        response = requests.request("GET", url, headers=headers, params=querystring) 
        #put the results in a variable
        json_results = json.loads(response.text)
        # The JSON is a dictionary. Call the passivedns key in the dictionary and assign it to a variable. 
        the_pdns = json_results['passivedns']
        # Create a variable that will help us order the CSV columns the way we want it before we write the rows to the file.
        the_order = [7, 4, 3, 1, 2, 6, 5, 0]
        # The rows will be made into lists for manipulation later. Lets define the location of the timestamps so we can play with them.
        timestamps = [1, 2]
        if the_pdns == []:
            print("\n\nNo results found for " + entity)
        else:
            print("Results found for " + entity)
            for pdns in the_pdns:
                if count == 0:
                    # Make the dictionary values into a list so we can modify the contents of the header.
                    header = list(pdns.keys()) + ["PDNS Entity"]
                    # The times will be manipulated later on in the script. Lets make it clear that they are UTC, shall we?
                    for x in timestamps:
                        header[x] = header[x] + " (UTC)"
                    # Reorder the header before writing
                    csv_complete(header, the_order)
                    count += 1
                # Before writing the final CSV file data rows, we want to convert the ISO timestamps into a format usable by Exel.
                # First we make the dictionary values into lists so we can modify the contents
                the_values = list(pdns.values()) + [entity]
                # Then we call the "column" for created, updated, and critical updated times and modify them.
                try:
                    for x in timestamps:
                        the_values[x] = re.sub(r"(\d{4})\x2d(\d{2})\x2d(\d{2})T(\d{2}\x3a\d{2}\x3a\d{2})\x2e\d{3}Z",r"\2/\3/\1 \4",the_values[x])
                except:
                    pass
                csv_complete(the_values, the_order)

# Returns a list of event-objects for a specified Detection
def list_detection_events():
    detection_uuid_input = ''
    detection_uuid_input = input('Please input detection_uuid. Multiples can be separated by a comma: ')
    detection_uuid_list = detection_uuid_input.split(",")
    local_rule_db = {}
    # Counter variable used for writing header row to the CSV file
    count = 0
    for detection_uuid in detection_uuid_list:
        detection_uuid = detection_uuid.strip()
        url = "https://detections.icebrg.io/v1/events" 
        querystring = {"detection_uuid" : detection_uuid, "limit" : "1000"} 
        headers = {"Content-Type": "application/json","cookie":"IBToken=" + api_token} 
        response = requests.request("GET", url, headers=headers, params=querystring)
        json_results = json.loads(response.text)
        the_events = json_results['events']
        # Create a variable that will help us order the CSV columns the way we want it before we write the rows to the file.
        the_order = [38, 5, 39, 1, 24, 25, 31, 32, 26, 27, 28, 29, 33, 34, 35, 36, 37, 14, 15, 17, 18, 0, 2, 3, 4, 6, 9, 10, 11, 12, 13, 16, 19, 20, 21, 22, 23, 7, 8]    
        # The rows will be made into lists for manipulation later. Lets define the location of the timestamps so we can play with them.
        timestamps = [5]
        # We want to add a column for rule name into the sheet. We don't want to query icebrg with each row, so lets create a db so that unique rules will query only once.        
        for event in the_events:
            # Create and empty rule_name variable
            rule_name = ''
            #This if/else pair will see if we need to query icebrg for the rule or not.
            if event['rule_uuid'] in local_rule_db.keys():
                rule_name = local_rule_db[event['rule_uuid']]
            # This else is the alternative for the if function above. If the rule_uuid isn't a key in the local_rule_db variable, then query icebrg.
            else:
                # Lets query the rule_uuid and add the rule name as a second row in the report
                # We will take the event rule_uuid and search for it.
                rule_search_url = "https://detections.icebrg.io/v1/rules/" + event['rule_uuid']
                rule_search_response = requests.request("GET", rule_search_url, headers=headers)
                #put the results in a variable
                rule_search_json_results = json.loads(rule_search_response.text)
                rule_name = rule_search_json_results['rule']['name']
                local_rule_db[event['rule_uuid']] = rule_search_json_results['rule']['name']
            # This IF will define and write the header of the CSV file
            if count == 0:
                # Make the dictionary values into a list so we can modify the contents of the header.
                header = ['rule_uuid'] + list(event['event'].keys()) + ['src_' + sub for sub in list(event['event']['src'].keys())] + ['dst_' + sub for sub in list(event['event']['dst'].keys())] + ["detection_uuid"] + ["rule_name"]
                # The times will be manipulated later on in the script. Lets make it clear that they are UTC, shall we?
                for x in timestamps:
                    header[x] = header[x] + " (UTC)"
                # Reorder the header before writing
                try:
                    csv_complete(header, the_order)
                except:
                    pass
                count += 1
            # Before writing the final CSV file data rows, we want to convert the ISO timestamps into a format usable by Exel.
            # First we make the dictionary values into lists so we can modify the contents
            the_values = [event['rule_uuid']] + list(event['event'].values()) + list(event['event']['src'].values()) + list(event['event']['dst'].values()) + [detection_uuid] + [rule_name]
            for x in timestamps:
                the_values[x] = re.sub(r"(\d{4})\x2d(\d{2})\x2d(\d{2})T(\d{2}\x3a\d{2}\x3a\d{2})\x2e\d{3}Z",r"\2/\3/\1 \4",the_values[x])
            try:
                csv_complete(the_values, the_order)
            except:
                pass

file_path = os_identification()
options = user_input()
end_file = name_file()

run_query()
print(end_file + " created.")
