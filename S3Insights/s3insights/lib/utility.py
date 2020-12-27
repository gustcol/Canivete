#   Copyright 2020 Ashish Kurmi
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License

import logging
import random
import os
import string
import sys
from functools import wraps

from lib import config


def setup_logging(level):
    """ Setup logging for the current session

    Arguments:
        level {integer} -- Log level
    """
    logger = logging.getLogger()
    logger.setLevel(level)
    if len(logger.handlers) == 0:
        # This is a local execution environment. Let's emit logs to stdout
        loghandler = logging.StreamHandler()
        loghandler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
        logger.addHandler(loghandler)

    # Let's reduce log noise from the following dependencies
    logging.getLogger('boto3').setLevel(logging.CRITICAL)
    logging.getLogger('botocore').setLevel(logging.CRITICAL)


def get_resource_name(run_id, resourcetype, postfix=None):
    """ Get resource name for a specific particular execution

    Arguments:
        run_id {string} -- run_id for the current Step Function execution
        resourcetype {string} -- AWS resource type

    Keyword Arguments:
        postfix {string} -- Postfix for the name (default: {None})

    Returns:
        string -- Resource name
    """
    name = f'{config.DeploymentDetails.deployment_name}-{run_id}-{resourcetype}'

    if postfix is not None:
        name = name + "-" + postfix
    return name


def get_file_path(caller, relative_path):
    """ Get file path

    Arguments:
        caller {string} -- Caller path
        relative_path {string} -- Relative file path

    Returns:
        string -- Full file path to the given file
    """
    return os.path.join(os.path.dirname(caller), relative_path)


def random_string(stringLength=10):
    """ Generate random string

    Keyword Arguments:
        stringLength {int} -- Random string lenth (default: {10})

    Returns:
        string -- Random string
    """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))


def compare_strings(string1, string2):
    """ Compare two strings

    Arguments:
        string1 {string} -- First string
        string2 {string} -- Second string

    Returns:
        boolean -- Flag indicating if both strings are equal
    """
    return string1.casefold() == string2.casefold()


class S3InsightsException(Exception):
    def __init__(self, *args, **kwargs):
        """ Custom exception for the project

        Arguments:
            Exception {exception} -- Base exception
        """
        Exception.__init__(self, *args, **kwargs)


def setup_logger(fn):
    """ Configure logger for the current session

    Arguments:
        fn {function} -- Function
    """
    @wraps(fn)
    def worker(*args, **kwargs):
        setup_logging(logging.INFO)
        return fn(*args, **kwargs)
    return worker
