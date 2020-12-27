#!/usr/bin/env python
# -*- coding: UTF-8 -*-
###############################################
## Purpose: Provies argument parsing capability
###############################################
import argparse

parser = argparse.ArgumentParser(description='''''')

parser.add_argument(
                    '-t', 
                    '--threads',
                    default=1,
                    type=int,
                    help='(optional) Number of Threads',
                   )

parser.add_argument(
                    '-o', 
                    '--output_file',
                    help='(optional) Modify the output folder, replaces the buckets_found.txt file',
                   )

parser.add_argument(
                    '-p', 
                    '--print_bucket_names',
                    action='store_true',
                    help='Print bucket names as they are attempted',
                   )

###########################################################################
########                      Types of search                      ########
###########################################################################
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument(
                    '-l',
                    '--list',
                    help='List file to use',
                   )
group.add_argument(
                    '-i',
                    '--input_permutations',
                    help='Input file with permutations already generated',
                   )
group.add_argument(
                    '-s',
                    '--string',
                    help='String to scan',
                   )
group.add_argument(
                    '-r',
                    '--random_string_options',
                    help='Chars to create random strings from, until script is stopped'
                   )
group.add_argument(
                    '-cp',
                    '--all_comb_perm',
                    help='Goes through all combinations and permutations of the string.  Requires the -c option'
                   )
parser.add_argument(
                    '-pp', 
                    '--prefix_or_postfix',
                    default="both",
                    help='(optional) Pick if you want to do add variablese to the "prefix" "postfix" or "both" or "None"',
                   )
parser.add_argument(
                    '-ao', 
                    '--acronyms_only',
                    action='store_true',
                    help='Only run checks on name acronyms',
                   )

###########################################################################
########                    AWS Credentials                        ########
###########################################################################
parser.add_argument(
                    '-ak', 
                    '--access_key',
                    help='AWS Access Key',
                   )

parser.add_argument(
                    '-sk', 
                    '--secret_key',
                    help='AWS Secret Key',
                   )

###########################################################################
########            Start/Stop point related items                 ########
###########################################################################
parser.add_argument(
                    '-a', 
                    '--start_after_value',
                    required=False, 
                    help='Start after this string in the list file (-l) or comb/perm search (-cp)',
                   )

parser.add_argument(
                    '-f', 
                    '--stop_at_value',
                    required=False, 
                    help='Stop once you reach this char; do not search it.  For use with -cp to segment searches',
                   )

parser.add_argument(
                    '-n', 
                    '--start_after_line_num',
                    type=int, 
                    required=False, 
                    help='Start after this line num in the list file',
                   )


###########################################################################
########     Number of charaters for random or comb/perm tests     ########
###########################################################################
parser.add_argument(
                    '-c', 
                    '--num_chars',
                    required=False, 
                    type=int, 
                    help='Number of chars the generated string should be',
                  ) 

parser.add_argument(
                    '-cr', 
                    '--num_chars_range',
                    required=False, 
                    help='Range of the number of chars the generated string should be, e.g. "-cr 3-4"',
                  )

#Compile the argument paser options
args = parser.parse_args()
