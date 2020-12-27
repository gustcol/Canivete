#!/usr/bin/env python
import threading
import Queue
import random, time
from lib.progressbar import ProgressBar
from lib.constants import *
from lib.logger import *
from module.check_bucket import *
from module.generate_strings import *

def createStringGenerator(search):
    while True:
        if search.num_chars:
            yield ''.join(random.choice(search.string_options) for i in range(search.num_chars))
        elif search.num_chars_range:
            lower_bound, upper_bound = search.num_chars_range.split("-")
            lower_bound = int(lower_bound.strip())
            upper_bound = int(upper_bound.strip())
            yield ''.join(random.choice(search.string_options) for i in range(random.randint(lower_bound, upper_bound)))


def run_random_search(search):
    #Create progressbar to show how many searches have been done, removing eta
    search.progressbar = ProgressBar(0)
    search.progressbar.fmt = '''%(percent)3d%% %(bar)s %(current)s/%(total_items)s   %(items_per_sec)s   Run time: %(run_time)s   Bucket: %(bucket_name)s'''

    buckets_found = get_buckets_found(search.output_file)


    #Get all public butets that have been found so far
    search.buckets_found = get_buckets_found(search.output_file)
    #Create a string generator
    search.string_generator = createStringGenerator(search)

    my_queue = Queue.Queue()
    for i in range(search.threads):
        t = threading.Thread(target=search_instance, args=(search, ))
        my_queue.put(t)

    #Run all of the threads
    while not my_queue.empty():
        my_queue.get().start()


def search_instance(search):
    while True:
        try:
            bucket_name = search.string_generator.next()

            bucket_names = get_string_variations(bucket_name, search.prefix_postfix_option, acronyms_only_option=False)

            for bn in bucket_names:
                check_s3_bucket(bucket_name=bn, access_key=search.access_key, secret_key=search.secret_key, output_file=search.output_file)

                #Increment progress and sleep              
                if search.print_bucket_names:
                    search.progressbar.total_items += 1
                    search.progressbar(print_bucket_names=search.print_bucket_names, bucket_name=bn)
                else:
                    search.progressbar.total_items += 1
                    search.progressbar()

                time.sleep(sleep_sec_between_attempts)
                    
        #Generator is empty...done
        except StopIteration:
            break
        #Generator is already running for another thread
        except ValueError:
            pass
        #Catchall for other issues
        except:
            pass