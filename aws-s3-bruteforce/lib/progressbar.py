#!/usr/bin/python
#
# Forked from Romuald Brunet, https://stackoverflow.com/questions/3160699/python-progress-bar
#
from __future__ import print_function
import sys
import re
import time, datetime


class ProgressBar(object):
    def __init__(self, total_items):
        """Initialized the ProgressBar object"""
        #Vars related to counts/time
        self.total_items = total_items
        self.current = 0
        self.finished = False
        self.start_epoch = None         #Set to none, start when first iteration occurs
        #Vars related to output
        self.width = 40                 #Length of progress bar
        self.symbol = "#"               #Needs to be 1 char
        self.output = sys.stderr
        self.fmt = '''%(percent)3d%% %(bar)s %(current)s/%(total_items)s   %(items_per_sec)s   ETA: %(eta)s  %(bucket_name)s'''
        assert len(self.symbol) == 1    #If higher, progress bar won't populate properly
        assert self.width <= 150        #If higher, it'll takeup more than one line of text


    def __call__(self, num_compelted=1, print_bucket_names=False, bucket_name=""):
        """Actions to run when progress is run"""

        #Initialize the start time as the first iteration (just in case progress bar is initialized early)
        if self.start_epoch is None:
            self.start_epoch = int(time.time())

        #Update calculations/values
        self.current += num_compelted

        try:
            percent = self.current / float(self.total_items)
        except:
            percent = 0
        
        size = int(self.width * percent)
        run_time = time.time() - self.start_epoch
        remaining = self.total_items - self.current
        try:
            time_left = (run_time/self.current) * remaining
        except:
            time_left = 0


        #Args to populate into fmt
        if print_bucket_names:
            bn = "Bucket: %s\n" % (bucket_name)
        else:
            bn = ""
        args = {
            'percent': (percent * 100),
            'bar': '''[{symbols}{spaces}]'''.format(symbols=(self.symbol * size), spaces=' ' * (self.width - size)),
            'current': "{:,}".format(self.current),
            'total_items': "{:,}".format(self.total_items),
            'items_per_sec': "{items_per_sec}/sec".format(items_per_sec="{:,}".format(int(self.current / run_time))),
            'eta': self.get_eta(int(time_left)),
            'run_time': self.get_eta(run_time),
            'bucket_name': bn,
        }

        #Print the update
        print('\r' + self.fmt%args, file=self.output, end='     ')


    def get_eta(self, time_left):
        """Print the num hour, min and/or sec for the given number of seconds"""
        time_remaining = time.gmtime(time_left)
        months_left = time_remaining.tm_mon-1
        days_left = time_remaining.tm_mday-1
        if months_left:
            return "{months_left}m {days_left}d {hr}h {min}m {sec}s".format(months_left=months_left, days_left=days_left, hr=time_remaining.tm_hour, min=time_remaining.tm_min, sec=time_remaining.tm_sec)
        elif days_left:
            return "{days_left}d {hr}h {min}m {sec}s".format(days_left=days_left, hr=time_remaining.tm_hour, min=time_remaining.tm_min, sec=time_remaining.tm_sec)
        elif time_remaining.tm_hour:
            return "{hr}h {min}m {sec}s".format(hr=time_remaining.tm_hour, min=time_remaining.tm_min, sec=time_remaining.tm_sec)
        elif time_remaining.tm_min:
            return "{min}m {sec}s".format(min=time_remaining.tm_min, sec=time_remaining.tm_sec)
        else:
            return "{sec}s".format(sec=time_remaining.tm_sec)


    def done(self):
        """Prints completion statement, only once"""
        #Be sure done hasn't already been called, set if not
        if not self.finished:
            self.finished = True

            run_time = time.gmtime(time.time() - self.start_epoch)

            final_output = '''
FINISHED at {date_time}
Total time: {total_time}
Total completed: {total_items_done}'''.format(
                date_time = str(datetime.datetime.now()),
                total_items_done = self.current,
                total_time = "{hr}h {min}m {sec}s".format(hr=run_time.tm_hour, min=run_time.tm_min, sec=run_time.tm_sec)
            )

            #Print final output
            print('\n{final_output}\n'.format(final_output=final_output), file=self.output)
