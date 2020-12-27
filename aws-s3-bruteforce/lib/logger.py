#!/usr/bin/env python
import os, ast
from lib.constants import *

def get_buckets_found(output_file=None):
    """Return a list of comb/perm public buckets that have been found"""
    bucket_names = []
    try:
        if not output_file:
            output_file = "%s/buckets_found.txt" % (list_dir)
        with open(output_file, 'r') as f:
            for line in f:
                if line.strip():
                    try:
                        bucket_names.append(ast.literal_eval(line.strip())["name"])
                    except:
                        pass
        return bucket_names
    except:
        return bucket_names


def log_bucket_found(bucket_result, output_file=None):
    if not output_file:
        output_file = "%s/buckets_found.txt" % (list_dir)

    """Writes potentially open buckets to a file"""
    f = open(output_file, "a")
    f.write("{bucket_result}\n".format(bucket_result=str(bucket_result)))
    f.close()
