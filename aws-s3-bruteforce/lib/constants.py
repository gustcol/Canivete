#!/usr/bin/env python
import os

lib_dir = os.path.dirname(os.path.realpath(__file__))
main_dir = os.path.dirname(os.path.dirname(__file__))
list_dir = "%s/list" % (main_dir)

base_url = "https://s3.amazonaws.com/"

#Seconds to sleep between attempts
sleep_sec_between_attempts = .05

#Company entity endings to check for and add to list, with them removed
entities = [
                " Inc", " Incorporated", 
                " Co", "Company", 
                " Corp", " Corporation"
                " LLC",
                " Ltd", "Limited",
           ]

#Things to replace spaces with
space_replacements = ["", "-", "_"]

#Prefixes and postfixes to add to the strings
prefix_postfix_separators = ["", ".", "-", "_"]

# Loaded from the file specified in prefixes_postfixes_file
prefixes_postfixes_file = "%s/prefixes_postfixes.txt" % (list_dir)
prefixes_postfixes = []
with open(prefixes_postfixes_file) as f:
    prefixes_postfixes = [line.rstrip('\n') for line in f]

#Domains to add onto the string  (excluding .gov, .edu, etc as that will be more targeted)
#This is removed for right now because it saw few positive results
# domains = [".com", ".net", ".org"]
domains = []
