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

def guided_mode():
    address_range = str
    source_type = {'1':'Manually Input','2':'Existing TXT/CSV'}
    source_selection = int
    print('\nPlease select range source: ')
    while source_selection not in [1, 2]:
        source_selection = int(option_display(source_type))
    if source_selection == 1:
        address_range = input('Input a space separated list of ranges (i.e. 172.16.0.0-172.16.0.255 192.168.0.0-192.168.0.255): ' )
        address_range = address_range.split(' ')
        cidr_matchup(address_range)
    elif source_selection == 2:
        original_file = input('\n' + r'Please provide the full path to TXT/CSV file (i.e. C:\Path\to\file.csv): ')
        if original_file[-4:].lower() == '.csv':
            column_header = input('\nPlease provide the column header containing the range: ')
            csv_file_read(original_file, column_header)
        elif original_file[-4:].lower() == '.txt':
            txt_file_read(original_file)
        else:
            parser.error('Please provide a TXT file with ranges in new lines or a CSV file with the column containing ranges.')

def open_file(original_file):
    # Read the original file. 
    data = open(original_file,encoding='utf_8_sig')
    print('\nReading file:\n{}'.format(original_file))
    return data

def csv_file_read(original_file, column):
    # Read the CSV Data
    csv_data = csv.reader(open_file(original_file))
    # Make a list of lists of the csv data
    orig_data_lines = list(csv_data)
    # Find the index for the provided IP column
    header = orig_data_lines[0]
    header.insert(header.index(column) + 1, 'CIDR')
    csv_complete(header)
    source_column = orig_data_lines[0].index(column)
    cidr_column = header.index('CIDR')
    for line in tqdm(orig_data_lines[1:]):
        address_range = line[source_column]
        address_range = address_range.split(',')
        the_cidr = ''
        for r in address_range:
            # Split the address range into two separate IPs in a simple list.
            address_range_split = r.split('-')
            found_cidr = []
            try:
                if len(address_range_split) == 2:
                    found_cidr = netaddr.cidr_merge(netaddr.iter_iprange(address_range_split[0], address_range_split[1]))
                elif len(address_range_split) == 1:
                    found_cidr = netaddr.cidr_merge(netaddr.iter_iprange(address_range_split[0], address_range_split[0]))
                for cidr in found_cidr:
                    the_cidr += str(cidr) + '\n'
            except:
                continue
        the_cidr = the_cidr.rstrip('\n')
        line.insert(header.index('CIDR'), the_cidr)
        csv_complete(line)
            
    
def txt_file_read(original_file):
    # open the txt file
    txt_data = open_file(original_file)
    # Read the txt file
    the_data = txt_data.read()
    txt_data_list = [(x.strip() and x.replace(' ', '')) for x in the_data.split('\n')]
    cidr_matchup(txt_data_list)

def cidr_matchup(address_range):
    cidr_obj_list = {}
    print('Finding CIDRs ')
    for r in tqdm(address_range):
        # Split the address range into two separate IPs in a simple list.
        address_range_split = r.split('-')
        cidr_obj_list[r] = netaddr.cidr_merge(netaddr.iter_iprange(address_range_split[0], address_range_split[1]))
    
    header = ['PROVIDED RANGE','CIDR']
    csv_complete(header)
    
    print('Writing results')
    for obj in tqdm(cidr_obj_list):
        line = []
        line.insert(header.index('PROVIDED RANGE'), obj)
        the_cidr = ''
        for cidr in cidr_obj_list[obj]:
            the_cidr += str(cidr) + '\n'
        the_cidr = the_cidr.rstrip('\n')
        line.insert(header.index('CIDR'), the_cidr)
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
    else:
        guided_mode()
           
    print("\nFile created:\n{}".format(end_file))
