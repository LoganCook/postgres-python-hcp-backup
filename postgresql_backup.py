#!/usr/bin/env python

"""
Original Author: Simon Brennan
Maintened By: Andrew Hill
Purpose: This code will backup all the databases on a postgresql server to an Hitachi Content Platform system
"""

import slackweb
import subprocess
import os
import socket
from datetime import datetime
import sys
import ssl
from boto.s3.connection import S3Connection
from boto.s3.key import Key
import logging
import json
from grandfatherson import MONDAY, to_delete


class HcpTenant:

    """
    Provides management to a HCP tenant using the Boto S3 API
    """

    def __init__(self, **kwargs):
        """
        Create the connection to the HCP
        """
        self.hostname = kwargs.get('hostname')
        self.namespace = kwargs.get('namespace')
        self.prefix = kwargs.get('prefix', '')
        self.delimiter = kwargs.get('delimiter', '.xz')
        self.quota = kwargs.get('quota', 0)
        access_key = kwargs.get('access_key')
        secret = kwargs.get('secret')
        _create_unverified_https_context = ssl._create_unverified_context
        ssl._create_default_https_context = _create_unverified_https_context
        s3 = S3Connection(aws_access_key_id=access_key,
                          aws_secret_access_key=secret, host=self.hostname)
        self.bucket = s3.get_bucket(self.namespace)

    def list(self):
        """
        Returns a Python dict of objects in the HCP bucket. K=timestamp, V=name
        """
        objects = {}
        json_list = self.bucket.list(prefix=self.prefix,
                                     delimiter=self.delimiter)
        for json_last_file in json_list:
            json_file = self.bucket.get_key(json_last_file.name)
            timestamp = datetime.strptime(json_file.last_modified,
                                          "%a, %d %b %Y %H:%M:%S GMT")
            objects[timestamp] = json_last_file.name.encode("ascii")

        return objects

    def delete(self, keyname):
        """
        Remove an object (S3 key) from the HCP bucket
        """
        obj = Key(self.bucket)
        obj.key = keyname
        obj.delete()

    def upload(self, filepath, keyname):
        """
        Add an object (S3 key) to the HCP bucket
        """
        obj = Key(self.bucket)
        obj.key = keyname
        obj.set_contents_from_filename(filepath)

    def rotate(self, filepath, keyname, days, weeks, months):
        """
        Upload an object to the HCP, rotating old files if needed
        """
        objects = self.list()
        del_list = sorted(to_delete(objects.keys(), days=days,
                                    weeks=weeks, months=months,
                                    firstweekday=MONDAY))
        for timestamp in del_list:
            name = objects[timestamp]
            message = "removing old object: {}".format(name)
            logging.debug(message)
            self.delete(name)

        message = "adding new object: {}".format(keyname)
        logging.debug(message)
        self.upload(filepath, keyname)


def main():

    # Read the config file
    try:
        with open('config.json') as config_file:
            config = json.load(config_file)
    except:
        message = "Unable to load configuration file"
        logging.critical(message)
        sys.exit(1)

    logging.basicConfig(filename=config["logging"]["file"],
                        level=config["logging"]["level"])

    # Calculate some variables
    slack = slackweb.Slack(url=config["slack"]["token"])
    now = datetime.now()
    hostname = socket.gethostname()
    directory = config["pgdump"]["tmpdir"]
    filename = now.strftime("%Y%m%d%H%M%S") + "-pgdump-" + hostname + ".xz"
    fullpath = "{}/{}".format(directory, filename)
    postgrescommand = "pg_dumpall | pxz -1 >" + fullpath

    message = "Backing up postgresql to HCP"
    logging.info(message)

    # Dump the databases from pg_dumpall and compress it
    try:
        ps = subprocess.Popen(postgrescommand, shell=True)
        output = ps.communicate()[0]
        logging.debug(output)
        logging.debug(now.strftime("%Y%m%d%H%M%S"))
        logging.debug(hostname)
        logging.debug("Uploading to HCP S3...")
    except ValueError:
        message = "There was an error running pg_dumpall"
        logging.error(message)
        slack.notify(text=message)
        sys.exit(1)
    if not os.path.isfile(filename):
        message = "I can't find the pgdump file in {}. I expected one!".format(directory)
        logging.error(message)
        slack.notify(text=message)
        sys.exit(1)

    # Upload the backup file to an HCP tenant/namespace using the Boto S3 protocol.
    try:
        tenant = HcpTenant(hostname="{}.{}".format(config["hcp"]["tenant"],
                           config["hcp"]["hostname"]),
                           namespace=config["hcp"]["namespace"],
                           access_key=config["hcp"]["access_key"],
                           secret=config["hcp"]["access_secret"])

        tenant.rotate(fullpath, filename,
                      days=config["rotation"]["days"],
                      weeks=config["rotation"]["weeks"],
                      months=config["rotation"]["months"])

    except:
        message = "Something went wrong uploading the PostgreSQL dump to the HCP!"
        logging.error(message)
        slack.notify(text=message)
        sys.exit(1)
    else:
        message = "Service postgresql backup successful."
        logging.info(message)
        slack.notify(text=message)

if __name__ == '__main__':
    main()
