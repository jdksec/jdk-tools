# Import the necessary modules
import xml.etree.ElementTree as ET
import argparse

# Define command line arguments for the script
parser = argparse.ArgumentParser()
parser.add_argument("file1", help="path to the first Nessus XML file")
parser.add_argument("file2", help="path to the second Nessus XML file")
args = parser.parse_args()

# Parse the XML files using ElementTree
tree1 = ET.parse(args.file1)
tree2 = ET.parse(args.file2)

# Get the root elements of the XML files
root1 = tree1.getroot()
root2 = tree2.getroot()

# Loop through all the Report elements in the second XML file
for report in root2.findall("Report"):
    # Find the ReportHost element with the same name in the first XML file
    host = root1.find("Report/ReportHost[@name='" + report.attrib["name"] + "']")

    # If the host does not exist in the first XML file, add it
    if host is None:
        root1.append(report)
    else:
        # Otherwise, merge the two ReportHost elements
        for item in report.findall("ReportItem"):
            host.append(item)

# Write the merged XML data to a new file
tree1.write("nessus_merged.xml")
