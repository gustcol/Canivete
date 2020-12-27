#!/usr/bin/env python
import threading
import Queue
import itertools
import random, time
from lib.progressbar import ProgressBar
from lib.constants import *
from lib.logger import *
from module.check_bucket import *
from module.generate_strings import *


def createStringGenerator(string_options, num_chars):
    for item in itertools.product(string_options, repeat=num_chars):
        yield "".join(item)


def run_comb_perm_search(search):
    #Create progressbar to show how many searches have been done, removing eta
    search.progressbar = ProgressBar(total_items=get_num_comb_perm(string_options=search.string_options, num_chars=search.num_chars))
    search.progressbar(num_compelted=0)

    #Get all public butets that have been found so far
    search.buckets_found = get_buckets_found(search.output_file)
    #Create a string generator
    search.string_generator = createStringGenerator(search.string_options, search.num_chars)

    #Check and see if a start after value was provided
    if search.start_after_value:
        search.start_after_found = False
    else:
        search.start_after_found = True

    #See if a stop at value is seen
    if search.stop_at_value:
        search.stop_at_found = False
    else:
        search.stop_at_found = False
    
    my_queue = Queue.Queue()
    for i in range(search.threads):
        t = threading.Thread(target=search_instance, args=(search, ))
        my_queue.put(t)

    #Run all of the threads
    while not my_queue.empty():
        my_queue.get().start()


def search_instance(search):
    #Run the search across all combinations/permutations
    while True:
        try:
            bucket_name = search.string_generator.next()

            #Check and see if you're at the stopping point
            if search.stop_at_value == bucket_name:
                search.stop_at_found = True
            if search.stop_at_value and search.stop_at_found:
                break

            #Check and see if the starting point exists or has been found
            if not search.start_after_found:
                if bucket_name == search.start_after_value:
                    search.start_after_found = True
                search.progressbar.total_items -= 1
                continue
            
            bucket_names = get_string_variations(bucket_name, search.prefix_postfix_option, acronyms_only_option=search.acronyms_only)
            for bn in bucket_names:
                check_s3_bucket(bucket_name=bn, access_key=search.access_key, secret_key=search.secret_key, output_file=search.output_file)

                #Just print the searched bucket variation, don't increment till done
                if search.print_bucket_names:
                    search.progressbar(print_bucket_names=search.print_bucket_names, bucket_name=bn, num_compelted=0)
                else:
                    search.progressbar()

            if search.print_bucket_names:
                search.progressbar(print_bucket_names=search.print_bucket_names, bucket_name=bucket_name)
            else:
                search.progressbar()

            time.sleep(sleep_sec_between_attempts)

        #Generator is empty...done
        except StopIteration:
            print "stop"
            break
        #Generator is already running for another thread
        except ValueError:
            print "value error"
            pass
        #Catchall for other issues
        except Exception as e:
            print e

def get_num_comb_perm(string_options, num_chars):
    """Gets the number of combintions/permutations for the given string and number of chars"""
    num_comb_perm = 0
    for item in itertools.product(string_options, repeat=num_chars):
        num_comb_perm += 1
    return num_comb_perm


