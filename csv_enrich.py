#Take multiple CSVs and merge rows by a value.
#Written By: https://github.com/TRaven/Cyber-Scripts
#Version: 2 BETA

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
    header = []
    data_lines = []
    match_list = []
    # Lets find out how many CSVs we're gonna merge.
    csv_count = 0
    while csv_count < 2:
        try:
            csv_count = int(input('How many CSV files will you merge? [2]: ') or 2)
        except ValueError:
            print('Please input a number.')
    # Ask the user for the csv locations as well as the column headers to compare

    csv_1 = input(r'Please provide the path to the primary CSV. (i.e. C:\Path\to\file.csv): ')
    csv_1_header = input('\n' + r'Please provide the header to be compared: ')
    
   
    # Lets start getting the secondary CSVs
    sec_csv_locations = {}
    csv_iter_count = 1
    while csv_iter_count < csv_count:
        sec_csv_locations[csv_iter_count] = []
        sec_csv_locations[csv_iter_count].append(input(r'Please provide the path to the next CSV. (i.e. C:\Path\to\file.csv): '))
        sec_csv_locations[csv_iter_count].append(input('\n' + r'Please provide the header to be compared: '))
        # It may help to differentiate the primary's columns from the appended secondary data by using a prefix.
        set_prefix = ''
        secondary_prefix = ''
        while set_prefix not in ['Y', 'N']:
            set_prefix = (input('\n' + r'Would you like these column headers to have a prefix? Y/[N]: ') or 'N').upper()
        if set_prefix == 'Y':
            secondary_prefix = input('\nPlease provide the desired prefix: ') + ' '
        sec_csv_locations[csv_iter_count].append(secondary_prefix)
        csv_iter_count += 1
    
    # Open the primary CSV
    data_1 = open(csv_1,encoding='utf_8_sig')
    csv_data_1 = csv.reader(data_1)
    # Make a list of lists of the csv data
    data_lines = list(csv_data_1)
    # Find the index for the provided column header for comparison.
    data_1_column = data_lines[0].index(csv_1_header)
    # Write the header line from this file to the header variable
    header = data_lines[0]
    
    # Lets start iterating through the user input secondary CSVs
    csv_iter_count = 1
    while csv_iter_count < csv_count:
        # Open the second CSV.
        data_2 = open(sec_csv_locations[csv_iter_count][0],encoding='utf_8_sig')
        csv_data_2 = csv.reader(data_2)
        # Make a list of lists of the csv data
        data_2_lines = list(csv_data_2)
        # Find the index for the provided column header for comparison.
        data_2_column = data_2_lines[0].index(sec_csv_locations[csv_iter_count][1])
        # Lets make the later searching faster by creating a dictionary of the comparison data from the secondary sheet being evaluated.
        # We'll set the key for this item to False so we can change it to True later if it's found in the primary data just so we can get a count of matches found.
        data_2_keys = []
        for line in data_2_lines[1:]:
            data_2_keys.append(line[data_2_lines[0].index(sec_csv_locations[csv_iter_count][1])].lower())
        # Add the input prefix to the secondary file's column headers. If none was input, it doesn't really matter it won't add anything.
        data_2_header_rename = [sec_csv_locations[csv_iter_count][2] + i for i in data_2_lines[0]]
        # Combine the headers from the Primary and Secondary CSVs.
        header += data_2_header_rename
        # Lets iterate through each line in the primary
        for line in data_lines[1:]:
            # We will isolate the indicator in the current line
            target = line[header.index(csv_1_header)].lower()
            # Search the keys we previously extracted from the selected column in the secondary.
            if target in data_2_keys:
                # Lets add the target that matched to the match_list so we can get a final count stat at the end of the script.
                if target not in match_list:
                    match_list.append(target)
                # If the Primary CSV target is found in the secondary CSV keys, iterate through each row from the secondary CSV.
                for line_2 in data_2_lines[1:]:
                    # Once the target enrichment data from the secondary is found, combine both rows so it shows up as one in the new CSV.
                    if target == line_2[data_2_lines[0].index(sec_csv_locations[csv_iter_count][1])].lower():
                        line += line_2
                        break
            # If there isn't a target match, add a bunch of blanks under each of the secondary csv's columns.
            # This is so that the next CSV to be evaluated will line up in the final CSV.
            else:
                line += [""] * len(data_2_lines[0])
        csv_iter_count += 1
    
    for line in data_lines:
        # Write the combined line to the new CSV.
        csv_complete(line)
    
    # Once every line has been iterated through and appended where possible, let the user know where the file is!
    print("\nMatches Found: {}".format(len(match_list)))
    print("File created:\n{}".format(end_file))
