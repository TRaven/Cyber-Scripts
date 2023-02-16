#This script will take a list of Hashes to search against VirusTotal and return specifie AV results. This will hlep you identify if your AV manufacturer detects a hash.
#Written By: https://github.com/TRaven/Cyber-Scripts
#Version: 1 Alpha

import requests, json, sys, os, csv
from datetime import datetime
from tqdm import tqdm

VT_api_key = 'API_KEY'
AV = 'Example: McAfee'

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
    end_file = file_path + current_date_time + '-VirusTotal' + AV + 'Lookup.csv'
    return end_file

# Order and write the rows. Basically replace "orderee" with either "header" or "the_values" and that's it.
def csv_complete(orderee):
    with open(end_file,mode='a+',newline='') as csv_file:
        # Create the CSV writer object
        csv_writer = csv.writer(csv_file)
        # Write the rows to the CSV file
        csv_writer.writerow(orderee)   

def dedup_list(x):
    return list(dict.fromkeys(x))

def hash_search(provided_hashes):
    # Lets iterate through each hash and assemble the query to make to VirusTotal
    for h in tqdm(provided_hashes):
        url = "https://www.virustotal.com/api/v3/files/" + h
        headers = {"accept": "application/json", "x-apikey": VT_api_key}
        response = requests.get(url, headers=headers)
        the_data = json.loads(response.text)
        
        # Now lets see if we get relevant data or an error and add the appropriate data to the dictionary.
        try:
            hashes[h] = the_data['data']['attributes']['last_analysis_results'][AV]
        except:
            hashes[h] = the_data['error']
    
    return hashes

def data_assemble(the_data):
    # The first element will show the provided hash, so lets add that as the first item in the header.
    header = ['PROVIDED HASH']
    # The values will ultiamtely be in a list of lists for each item. Lets initialize that here.
    csv_values = []
    # Lets start iterating through the data to find all of the unique potential headers.
    for item in the_data:
        header.extend(the_data[item].keys())
        header = dedup_list(header)
    # The ones that ended up with an error, lets move that to the end of the list to make sure errors are the last item on the CSV columns.
    if 'message' in header:
        header.sort(key='code'.__eq__)
        header.sort(key='message'.__eq__)
    # Now lets start generating the csv_values for the rows in the CSV.
    for item in the_data:
        # Make a list of empty values the same length as the header. This way we can just replace the appropriate items and have everything in the CSV line up.
        the_values = [''] * len(header)
        the_values[0] = item
        for x in the_data[item]:
            the_values[header.index(x)] = the_data[item][x]
        csv_values += [the_values]
    
    # Lets write the CSV!
    csv_complete(header)
    for x in csv_values:
        csv_complete(x)
    
    

if __name__ == '__main__':
    # Let's see what OS the user is using in order to find the right file path to use.
    file_path = os_identification()
    # We will name the final VirusTotal dump file here.
    end_file = name_file()
    # The hashes variable is ultimately what will be passed to assemble the data.
    hashes = {}
    # This is where the user's provided hashes will be stored.
    provided_hashes = []
    # Lets start asking the user for input.
    data_input = ''
    while bool(data_input) == False:
        data_input = input('Please provide your hashes to search: ')
    # If a user puts in a comma separated list, this is just a string. We can split that string into an actual list here.
    data_input_list = data_input.split(",")
    # A user may input a list with comma spaces and with the split above, the spaces will remain with the input data. To avoid problems, lets strip the spaces.
    for data in data_input_list:
        provided_hashes.append(data.strip())
    # Deduplicate the list
    provided_hashes = dedup_list(provided_hashes)
    
    # Now lets search the hashes against virus total
    hashes = hash_search(provided_hashes)
    # Once the search is done, lets assemble the data for writing to CSV.
    data_assemble(hashes)   
    
    # Once everything is done, lets tell the user where the CSV file is stored.
    print("\nFile created:\n{}".format(end_file))