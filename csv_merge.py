#Take two CSVs and merge rows by a value.
#Written By: https://github.com/TRaven/Cyber-Scripts
#Version: 1 BETA

import csv, sys, os
from datetime import datetime

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
    end_file = file_path + current_date_time + '-csvMerge.csv'
    return end_file

# Order and write the rows. Basically replace "orderee" with either "header" or "the_values" and that's it.
def csv_complete(orderee):
    with open(end_file,mode='a+',newline='') as csv_file:
        # Create the CSV writer object
        csv_writer = csv.writer(csv_file)
        # Write the rows to the CSV file
        csv_writer.writerow(orderee) 

if __name__ == '__main__':
    # Create a file path for the final file. This is the downloads folder.
    file_path = os_identification()
    end_file = name_file()
    # Ask the user for the csv locations as well as the column headers to compare
    csv_1 = input(r'Please provide the path to the primary CSV. (i.e. C:\Path\to\file.csv): ')
    csv_1_header = input('\n' + r'Please provide the header to be compared: ')
    csv_2 = input('\n' + r'Please provide the path to the second CSV. (i.e. C:\Path\to\file.csv): ')
    csv_2_header = input('\nPlease provide the header to be compared\nPlease note this will work best if these values are unique in the second CSV: ')
    # It may help to differentiate the primary's columns from the appended secondary data by using a prefix.
    set_prefix = ''
    secondary_prefix = ''
    while set_prefix not in ['Y', 'N']:
        set_prefix = input('\n' + r'Would you like your secondary column headers to have a prefix? Y/N: ').upper()
    if set_prefix == 'Y':
        secondary_prefix = input('\nPlease provide the desired prefix: ') + ' '
        
    # Open the primary CSV
    data_1 = open(csv_1,encoding='utf_8_sig')
    csv_data_1 = csv.reader(data_1)
    # Make a list of lists of the csv data
    data_1_lines = list(csv_data_1)
    # Find the index for the provided column header for comparison.
    data_1_column = data_1_lines[0].index(csv_1_header)
    
    # Open the second CSV.
    data_2 = open(csv_2,encoding='utf_8_sig')
    csv_data_2 = csv.reader(data_2)
    # Make a list of lists of the csv data
    data_2_lines = list(csv_data_2)
    # Find the index for the provided column header for comparison.
    data_2_column = data_2_lines[0].index(csv_2_header)
    # Lets make the later searching easier on the system by creating a list of the comparison data from the second sheet.
    data_2_keys = []
    for line in data_2_lines[1:]:
        data_2_keys.append(line[data_2_lines[0].index(csv_2_header)])
    
    
    # FINALIZE
    data_2_header_rename = [secondary_prefix + i for i in data_2_lines[0]]
    header = data_1_lines[0] + data_2_header_rename
    csv_complete(header)
    for line in data_1_lines[1:]:
        # We will isolate the indicator in the current line
        target = line[header.index(csv_1_header)].lower()
        if target in data_2_keys:
            for line_2 in data_2_lines[1:]:
                if target == line_2[data_2_lines[0].index(csv_2_header)]:
                    line = line + line_2
        csv_complete(line)    

    print("\nFile created:\n{}".format(end_file))