#This script will take a list of IP ranges and find the CIDR ranges that apply to the range.
#Written By: https://github.com/TRaven/Cyber-Scripts
#Version: 1 Alpha

import netaddr, argparse, sys, os, csv
from datetime import datetime
from tqdm import tqdm

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
    end_file = file_path + current_date_time + '-CIDRmatch.csv'
    return end_file

# Order and write the rows. Basically replace "orderee" with either "header" or "the_values" and that's it.
def csv_complete(orderee):
    with open(end_file,mode='a+',newline='') as csv_file:
        # Create the CSV writer object
        csv_writer = csv.writer(csv_file)
        # Write the rows to the CSV file
        csv_writer.writerow(orderee)            

# Ask the user for what they're looking for.
def option_display(opt_dict):
    selection = ''
    while selection not in opt_dict.keys():
        for key, value in opt_dict.items():
            print('\t({}) {}'.format(key, value))
        selection = input('Selection: ')
    return selection

# This will give the user prompts for what they want to do.
def guided_mode():
    address_range = str
    source_type = {'1':'Manually Input','2':'Existing TXT/CSV'}
    source_selection = int
    
    # Ask they user where the ranges are coming from based on the contents of source_type above.
    print('\nPlease select range source: ')
    while source_selection not in [1, 2]:
        source_selection = int(option_display(source_type))
    # If we're Manually inputting
    if source_selection == 1:
        address_range = input('Input a space separated list of ranges (i.e. 172.16.0.0-172.16.0.255 192.168.0.0-192.168.0.255): ' )
        address_range = address_range.split(' ')
        cidr_matchup(address_range)
    
    # IF we're going to read a TXT/CSV file
    elif source_selection == 2:
        # The user will input a file location.
        original_file = input('\n' + r'Please provide the full path to TXT/CSV file (i.e. C:\Path\to\file.csv): ')
        # If the file is a CSV, they will need to give a column header. Then we can run the csv function.
        if original_file[-4:].lower() == '.csv':
            column_header = input('\nPlease provide the column header containing the range: ')
            csv_file_read(original_file, column_header)
        # If the file is a TXT, we can run the TXT function.
        elif original_file[-4:].lower() == '.txt':
            txt_file_read(original_file)
        # If the file is not CSV/TXT, we'll just present an error.
        else:
            parser.error('Please provide a TXT file with ranges in new lines or a CSV file with the column containing ranges.')

def open_file(original_file):
    # Read the original file. 
    data = open(original_file,encoding='utf_8_sig')
    print('\nReading file:\n{}'.format(original_file))
    return data

# This function will dictate how we leverage and uiltimately write a CSV file.
# We will take the original CSV and insert our enriched data to the original.
def csv_file_read(original_file, column):
    # Read the CSV Data
    csv_data = csv.reader(open_file(original_file))
    # Make a list of lists of the csv data
    orig_data_lines = list(csv_data)
    # Find the index for the provided range column
    header = orig_data_lines[0]
    # Lets insert our CIDR column after the provided column of ranges.
    header.insert(header.index(column) + 1, 'CIDR')
    # Write the header.
    csv_complete(header)
    # Lets define where the index for the source is going to be in all the subsequent rows.
    source_column = orig_data_lines[0].index(column)
    # When we write the CIDRs to the file, lets make sure to grab the appropriate index so that it lines up with the CIDR column.
    cidr_column = header.index('CIDR')
    # Now we iterate through the data lines (rows) in the original CSV.
    for line in tqdm(orig_data_lines[1:]):
        # In the row, lets grab the range(s) to review
        address_range = line[source_column]
        # If the row has multiple ranges within the column separated by commas, we can split them up to make a list to iterate through.
        address_range = address_range.split(',')
        # Lets create an empty string for the final CIDR text block to put into the column for the current row.
        the_cidr = ''
        # Now we will go through each range present in the row.
        for r in address_range:
            # Split the address range into two separate IPs in a simple list.
            address_range_split = r.split('-')
            # Create an empty list that will contain the found cidrs that we will eventually write to the row.
            found_cidr = []
            # Sometimes a row may not have a range that can be used, so we will try to find a range, but if not, we can just skip it in the except.
            try:
                # If the range contains two IP addresses, lets use them as the first and last item of the range.
                if len(address_range_split) == 2:
                    found_cidr = netaddr.cidr_merge(netaddr.iter_iprange(address_range_split[0], address_range_split[1]))
                # Sometimes there will be a single IP with no range. If that's the case, just use it as the first and last IP in the range and provide a /32 i guess!
                elif len(address_range_split) == 1:
                    found_cidr = netaddr.cidr_merge(netaddr.iter_iprange(address_range_split[0], address_range_split[0]))
                # Once the CIDRs are found, we can go through and add them to the string block that will be written to the column eventually.
                for cidr in found_cidr:
                    the_cidr += str(cidr) + '\n'
            # If there's an exception, just continue; don't kill the script..
            except:
                continue
        # Once all of the ranges have been reviewed and all of the CIDRs written to the CIDR block, you will have a new line at the end of it. Remove it.
        the_cidr = the_cidr.rstrip('\n')
        # Add the found CIDRs to the CIDR column for the row.
        line.insert(header.index('CIDR'), the_cidr)
        # Write this row!
        csv_complete(line)
            
    
def txt_file_read(original_file):
    # open the txt file
    txt_data = open_file(original_file)
    # Read the txt file
    the_data = txt_data.read()
    # Here we will add all of the ranges in new lines to a list. We'll also kill any uneccessary white space.
    txt_data_list = [(x.strip() and x.replace(' ', '')) for x in the_data.split('\n')]
    # Send these ranges through the CIDR matchup funciton.
    cidr_matchup(txt_data_list)

def cidr_matchup(address_range):
    cidr_obj_list = {}
    print('Finding CIDRs ')
    # Iterate through each range in the list.
    for r in tqdm(address_range):
        # Split the address range into two separate IPs in a simple list.
        address_range_split = r.split('-')
        # If the range contains two IP addresses, lets use them as the first and last item of the range.
        if len(address_range_split) == 2:
            cidr_obj_list[r] = netaddr.cidr_merge(netaddr.iter_iprange(address_range_split[0], address_range_split[1]))
        # Sometimes there will be a single IP with no range. If that's the case, just use it as the first and last IP in the range and provide a /32 i guess!
        elif len(address_range_split) == 1:
            found_cidr = netaddr.cidr_merge(netaddr.iter_iprange(address_range_split[0], address_range_split[0]))
    
    # Lets create then write the header to the new CSV.
    header = ['PROVIDED RANGE','CIDR']
    csv_complete(header)
    
    # Now we will start iterating through the dictionary to write a row with the provided range to the first column and then the identified CIDRs to the second.
    print('Writing results')
    for obj in tqdm(cidr_obj_list):
        # Start with a blank line.
        line = []
        # Put in the provided range (the dictionary's key) in column 1.
        line.insert(header.index('PROVIDED RANGE'), obj)
        # Lets create an empty string for the final CIDR text block to put into the column for the current row.
        the_cidr = ''
        # Iterate through each value for each key adding it to a string block and add a new line at the end of each.
        for cidr in cidr_obj_list[obj]:
            the_cidr += str(cidr) + '\n'
        # Once all of the ranges have been reviewed and all of the CIDRs written to the CIDR block, you will have a new line at the end of it. Remove it.
        the_cidr = the_cidr.rstrip('\n')
        # Add the found CIDRs to the CIDR column for the row.
        line.insert(header.index('CIDR'), the_cidr)
        # Write this row!
        csv_complete(line)

if __name__ == '__main__':
    # See what OS the user is using in order to find the right file path to use.
    file_path = os_identification()
    # We will name the final file here.
    end_file = name_file()
    address_range = []
    
    parser = argparse.ArgumentParser(
        prog = 'cidrFromRange.py',
        description = 'This script will take a list of IP ranges and find the CIDR ranges that apply to the range.',
        epilog = 'Written By: https://github.com/TRaven/Cyber-Scripts'
        )
    
    parser.add_argument('-r', '--range', help='Input a space separated list of ranges to review (i.e. 172.16.0.0-172.16.0.255 192.168.0.0-192.168.0.255)', nargs='*')
    parser.add_argument('-f', '--file', help='Use a TXT or CSV file that contains a column with ranges. If you get an error, try enclosing path in quotes.')
    parser.add_argument('-c', '--column', help='When using a CSV file, provide the column header where the ranges will be located.')
    parser.add_argument('-g', '--guided', help='This will send you through a step by step guided mode.', action='store_true')
    args = parser.parse_args()
    
    #We need to check if the user provded a column without a csv file as this won't work.
    if ((not args.column is None) and args.file is None):
        parser.error('The -c COLUMN argument requries the -f FILE to be defined with a CSV.')
        
    # If arguemnts are given, run functions for the appropriate arguments.
    if len(sys.argv) > 1:
        if args.guided is True:
            guided_mode()
        elif not args.range is None:
            address_range = args.range
            cidr_matchup(address_range)
        elif not args.file is None:
            if args.file[-4:].lower() == '.csv':
                if args.column is None:
                    parser.error('A CSV file requries the -c COLUMN to be defined.')
                else:
                    csv_file_read(args.file, args.column)
            elif args.file[-4:].lower() == '.txt':
                txt_file_read(args.file)
            else:
                parser.error('Please provide a TXT file with ranges in new lines or a CSV file with the column containing ranges.')
    # If no arguments are given, just run the guided mode.
    else:
        guided_mode()
    
    # Let the people know where the new CSV has been written!
    print("\nFile created:\n{}".format(end_file))
