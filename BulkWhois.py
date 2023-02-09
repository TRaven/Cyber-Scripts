#This script will take a CSV column or a list of IPs to perform whois queries on them.
#Written By: https://github.com/TRaven/Cyber-Scripts
#Version: 2 BETA

from requests import get
from ipaddress import ip_address, ip_network
from ipwhois import IPWhois
from datetime import datetime
from tqdm import tqdm
from OTXv2 import OTXv2, IndicatorTypes
import socket, json, re, csv, os, sys, whois

# OTX API Key for the OTX search. Create a free OTX account to get a key.
otx = OTXv2("ALIENVAULT_OTX_API_KEY")

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
    end_file = file_path + current_date_time + '-WHOISLookup.csv'
    return end_file

# Order and write the rows. Basically replace "orderee" with either "header" or "the_values" and that's it.
def csv_complete(orderee):
    with open(end_file,mode='a+',newline='') as csv_file:
        # Create the CSV writer object
        csv_writer = csv.writer(csv_file)
        # Write the rows to the CSV file
        csv_writer.writerow(orderee)            

def otx_lookup(data_list):
    global otx_results
    print('\nPerforming OTX lookup on {} unique {}s:'.format(len(data_list),query_type[query_selection]))
    for indicator in tqdm(data_list):
        if query_selection == '1':
            if ip_address(indicator).is_global == True:
                try:
                    response = otx.get_indicator_details_full(getattr(IndicatorTypes, query_type[query_selection]), indicator)
                    otx_results.append(response)
                except:
                    continue
        elif query_selection == '2':
            try:
                response = otx.get_indicator_details_full(getattr(IndicatorTypes, query_type[query_selection]), indicator)
                otx_results.append(response)
            except:
                continue
    return otx_results

# This function performs the WHOIS lookup.
def whois_lookup(data_list):
    global whois_results
    print('\nPerforming WHOIS on {} unique {}s:'.format(len(data_list),query_type[query_selection]))
    # Query selection 1 is IPv4
    if query_selection == '1':
        for ip in tqdm(data_list):
            identified = False
            # We only want to search public IPs
            if ip_address(ip).is_global == True:
                # If quick searching is enabled, we will try to see if the subnet has already been queried that way we save query time by using data already pulled.
                if ip_quick_search == 'Y':
                    count = 0
                    while count < len(whois_results.keys()):
                        try:
                            # Look at each cidr in the whois results dictionary until you find it. If you find it, we break out of the loop. If not, the next steps are teaken.
                            for entry in whois_results:
                                # Let's check if the ip in question has been identifed before the current loop, if so, stop, no more!!!
                                if identified == True:
                                    break
                                # If we're still not identified, lets go and iterate through each entry until we find a CIDR which the current IP matches.
                                else:
                                    # find a CIDR
                                    network = whois_results[entry]['asn_cidr']
#TEST                                    print("Identified {}. Checking {} against {} from {}".format(str(identified), ip, network, entry))
                                    # If the IP is in the current CIDR, "identified" will be true.
                                    identified = ip_address(ip) in ip_network(network)
                                    count += 1
                                    # If identified becomes true, we'll add the relevant WHOIS result to the IP's entry in the dictionary.
                                    if identified == True:
#TEST                                        print("Skipping {}".format(ip))
                                        whois_results[ip] = whois_results[entry]
                            break
                        except:
                            continue
                # If the ip didn't match up with one of the CIDRs already queried, lets run the whois.
                if identified == False:
                    try:
                        obj = IPWhois(ip)
                        response = obj.lookup_rdap(asn_methods=["whois"])
                        whois_results[ip] = response
                    except:
                        continue
    # Query selection 2 is Domain lookup.
    elif query_selection == '2':
        for domain in tqdm(data_list):
            try:
                query = whois.whois(domain)
                whois_results[domain] = query
            except:
                print('\n\nDOMAIN WHOIS ERROR\n\n')
                continue
    else:
        print("\nSomething went wrong and I don't know what you want me to query.")
        sys.exit()
    return whois_results

# If the user chooses to enrich their existing CSV file, the data will be assembled here.
def data_enricher(whois_results):
    # Firest we'll take the first line (header) of the original file and store it as header
    header = orig_data_lines[0]
    # Now we'll add all of the keys from the WHOIS results to a list
    whois_keys = list(list(whois_results.items())[0][1].keys())
    # Let's make it easier to determine what column the whois results apply to.
    # We'll iterate through each whois_key
    for element in whois_keys:
        # We'll append the current whois_key to the original column header
        combo = column_header + ' ' + element
        # Now we'll append this new header to the header list.
        header.append(combo)
    # Here we'll add a header for the address column when we extract that from the "asn_country_code" column
    if query_selection == '1':
        header.insert(header.index(column_header + ' asn_country_code'), column_header + ' Address')
    # Create additional Headers for OTX enrichment
    if otx_selection == 'Y':
        otx_headers = ['OTX Indicator URL', 'OTX Pulse Count','OTX Malware Families']
        header.extend(otx_headers)
    # Write the completed header to the new CSV file.
    csv_complete(header)
    # Lets assign each row after the header of the original CSV to the the_values list of lists
    the_values = orig_data_lines[1:]
    # We will iterate through each of the rows to add enrichment.
    print("Writing data to file:")
    for line in tqdm(the_values):
        # We will isolate the indicator in the current line
        target = line[header.index(column_header)].lower()
        # Search for the indicator in the list of IPs created when we got results from whois
        if target in whois_results.keys():
            # If the IP in the original CSV was found by whois, iterate through the whois results to find the whois reply
            for whois in whois_results:
                if query_selection == '1':
                    if whois == target:
                        # Once we found the WHOIS for the appropriate IP, we'll add the values for the whois dictionary as columns to the row. These should all fall under the appropriate column once complete.
                        line.extend(list(whois_results[whois].values()))
                        # Also extract the street address associated with the IP and add it to the appropriate column
                        try:
                            line.insert(header.index(column_header + ' Address'), list(whois['objects'].values())[0]['contact']['address'][0]['value'])
                        except:
                            line.insert(header.index(column_header + ' Address'), '')
                elif query_selection == '2':
                    if type(whois_results[whois]['domain_name']) == list:
                        whois_indicator = whois_results[whois]['domain_name'][0].lower()
                    elif type(whois_results[whois]['domain_name']) == str:
                        whois_indicator = whois_results[whois]['domain_name'].lower()
                    if whois_indicator == target:
                        # Once we found the WHOIS for the appropriate IP, we'll add the values for the whois dictionary as columns to the row. These should all fall under the appropriate column once complete.
                        line.extend(list(whois_results[whois].values()))
                        # Also extract the street address associated with the IP and add it to the appropriate column
                        
        # If the IP was not found by WHOIS, we'll try to add some context.
        else:
            # Here we will create blank columns where the WHOIS info would go that way we can add information to specific indices.
            for element in whois_keys:
                line.append('')
            # As the whois function is written to ignore private IPs, lets add to the description column that htis is a private IP.
            if query_selection == '1':
                if ip_address(target).is_private == True:
                    line.insert(header.index(column_header + ' asn_description'), 'THIS IS A PRIVATE IP')
                # Any other scenario will get a simple no whois information description.
                else:
                    line.insert(header.index(column_header + ' asn_description'), 'NO WHOIS INFORMATION FOUND')
        # Write the completed line to the new CSV file.
        # Start OTX Enrichment
        if otx_selection == 'Y':
            otx_malware_families = []
            otx_indicator_url = 'https://otx.alienvault.com/indicator/ip/' + target
            for otx_hit in otx_results:
                if target.lower() == otx_hit['general']['indicator'].lower():
                    otx_pulse_count = otx_hit['general']['pulse_info']['count']
                    for source in otx_hit['general']['pulse_info']['related']:
                        otx_malware_families.extend(otx_hit['general']['pulse_info']['related'][source]['malware_families'])
            otx_column_data = [otx_indicator_url, otx_pulse_count, otx_malware_families]
            line.extend(otx_column_data)
        csv_complete(line)
        

# This function creates the table for the CSV and passes the data to have the CSV created.
def not_enriched(whois_results):
    count = 0
    for whois_hit in whois_results:
        # This first IF will define and write the header of the CSV file
        if count == 0:
            # Make the dictionary values into a list so we can modify the contents of the header.
            header = list(whois_results[whois_hit].keys())
            # Create additional headers for IP searches
            if query_selection == '1':
                header.insert(0, 'PROVIDED IP ADDRESS')
                header.insert(header.index('asn_country_code'), 'Address')
            # Create additional Headers for OTX enrichment
            if otx_selection == 'Y':
                otx_headers = ['OTX Indicator URL', 'OTX Pulse Count','OTX Malware Families']
                header.extend(otx_headers)
            csv_complete(header)
            count += 1
        the_values = list(whois_results[whois_hit].values())
        if query_selection == '1':
            try:
                the_values.insert(0, whois_hit)
                the_values.insert(header.index('Address'), list(whois_results[whois_hit]['objects'].values())[0]['contact']['address'][0]['value'])
            except:
                continue
        # Start OTX Enrichment
        if otx_selection == 'Y':
            otx_malware_families = []
            if query_selection == '1':
                whois_indicator = whois_hit
                print(whois_indicator)
                otx_indicator_url = 'https://otx.alienvault.com/indicator/ip/' + whois_indicator
            elif query_selection == '2':
                if type(whois_results[whois_hit]['domain_name']) == list:
                    whois_indicator = whois_results[whois_hit]['domain_name'][0].lower()
                elif type(whois_results[whois_hit]['domain_name']) == str:
                    whois_indicator = whois_results[whois_hit]['domain_name'].lower()
                otx_indicator_url = 'https://otx.alienvault.com/indicator/domain/' + whois_indicator
            for otx_hit in otx_results:
                if whois_indicator == otx_hit['general']['indicator'].lower():
                    otx_pulse_count = otx_hit['general']['pulse_info']['count']
                    for source in otx_hit['general']['pulse_info']['related']:
                        otx_malware_families.extend(otx_hit['general']['pulse_info']['related'][source]['malware_families'])
            otx_column_data = [otx_indicator_url, otx_pulse_count, otx_malware_families]
            the_values.extend(otx_column_data)
        csv_complete(the_values)

# As users may input duplicate values or files may have duplicate values, lets remove those from the public IP list.
def dedup_list(x):
    return list(dict.fromkeys(x))


# Ask the user for what they're looking for.
def option_display(opt_dict):
    selection = ''
    while selection not in opt_dict.keys():
        for key, value in opt_dict.items():
            print('\t({}) {}'.format(key, value))
        selection = input('Selection: ')
    return selection



if __name__ == '__main__':
    # Here we define the type of queries to make
    query_type = {'1':'IPv4', '2':'DOMAIN'}
    # Here we define the source of the data to search.
    source_type = {'1':'Manually Input','2':'Existing CSV'}
    print('\nWhat do you want to query?')
    query_selection = option_display(query_type)
    ip_quick_search = ''
    if query_selection == '1':
        while ip_quick_search not in ['Y', 'N']:
            ip_quick_search = (input('\nWould you like to perform a quick IP search? Whois Data for previously queried CIDRs will be used for subsequent IPs ([Y]/N): ') or 'Y').upper()
    otx_selection = ''
    while otx_selection not in ['Y', 'N']:
        otx_selection = (input('\nWould you like to search Alienvault OTX for Threat Intel? (Y/[N]): ') or 'N').upper()
    print('\nPlease select {} source: '.format(query_type[query_selection]))
    source_selection = option_display(source_type)
    whois_results = {}
    otx_results = []
    orig_data_lines = []
    column_header = ''
    end_file = ''
    file_path = ''
    enrich_data = ''
    # Start a list for the final Public IPs to be stored in.
    data_list = []
    

            
    
    # Here are the actions performed if user chose to manually input indicators (source 1).
    if source_selection == '1':
        # Since this is manual and a existing file wasn't provided, lets see what OS the user is using in order to find the right file path to use.
        file_path = os_identification()
        # We will name the final WHOIS dump file here.
        end_file = name_file()
        # Ask the user for the IP or list of IPs to search for.
        data_input = input('\nPlease provide the {} to search. If multiple, separate by commas: '.format(query_type[query_selection])).lower()
        # If a user puts in a comma separated list, this is just a string. We can split that string into an actual list here.
        data_input_list = data_input.split(",")
        # A user may input a list with comma spaces and with the split above, the spaces will remain with the IPs. To avoid problems, lets strip the spaces.
        for data in data_input_list:
            data_list.append(data.strip())
        # Deduplicate the list
        data_list = dedup_list(data_list)
        # Now we will get the results of our search but we must first select the appropriate query by data type.
        whois_results = whois_lookup(data_list)
    
    # Here are the actions performed if option 2 is selected by the user.
    elif source_selection == '2':        
        # Ask the user for the file location
        original_file = input('\n' + r'Please provide the full path to CSV file (i.e. C:\Path\to\file.csv): ')
        # As the user for the column where the IPs are stored.
        column_header = input('\nPlease provide the column header containing the {}: '.format(query_type[query_selection]))
        # Name the file the original filename with _WHOIS_Lookup appended.
        end_file = re.sub(r"^(.*?)(.csv)",r"\1_WHOIS_Lookup\2",original_file)
        while enrich_data not in ['Y', 'N']:            
            enrich_data = (input('\nWould you like to enrich your existing data with lookup information? ([Y]/N): ') or 'Y').upper()
        

        # Read the original file. 
        data = open(original_file,encoding='utf_8_sig')
        print('\nReading file:\n{}'.format(original_file))
        # Read the CSV Data
        csv_data = csv.reader(data)
        # Make a list of lists of the csv data
        orig_data_lines = list(csv_data)
        # Find the index for the provided IP column
        source_column = orig_data_lines[0].index(column_header)
        # Using the IP column index, extract the ip for the query from each row.
        for line in orig_data_lines[1:]:
            data_list.append(line[source_column])
        # Deduplicate the list
        data_list = dedup_list(data_list)
        # Now we will get the results of our search but we must first select the appropriate query by data type.
        whois_results = whois_lookup(data_list)

    else:
        print("\nSomething went wrong and I don't know what you want me to query.")
        sys.exit()
    
    
    if otx_selection == 'Y':
        otx_results = otx_lookup(data_list)
    # Create a table from the results and write the new file.
    if enrich_data == 'Y':
        data_enricher(whois_results)
    else:
        not_enriched(whois_results)

    
    print("\nFile created:\n{}".format(end_file))
