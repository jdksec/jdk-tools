# creds to tomnomnom for the OG go script
import argparse


# create an argument parser
parser = argparse.ArgumentParser()

# add the arguments for the input files
parser.add_argument('--old', help='the old file to compare against')
parser.add_argument('--new', help='the new file to compare')

# parse the arguments
args = parser.parse_args()

# open the files
with open(args.old, 'r') as old_file, open(args.new, 'r') as new_file:
    # create a set to store the entries in the old file
    entries_in_old = set()

    # read the entries in the old file and add them to the set
    for line in old_file:
        entries_in_old.add(line.strip())

    # read the entries in the new file and print the ones that do not exist in the old file
    for line in new_file:
        entry = line.strip()
        if entry not in entries_in_old:
            print(entry)
