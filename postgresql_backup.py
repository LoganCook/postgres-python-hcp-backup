## Author: Simon Brennan
## Date: 18 Jan 2016 
## Purpose: This code will backup all the databases on a postgresql server to an Hitachi Content Platform system
## TODO: 
## Clean up the temporary file created by the script in /tmp
## Better error handling (Slack post on errors)
## Slack post on success
## Move Token and Tenant configuration to OS Environment variables

#!/bin/python
import subprocess #Used to fire up the postgresql backup via a shell
import pycurl #Wrapper around curl to push files into the HCP
import os
import socket #used to mainly get the hostname of the system this script runs on
from datetime import datetime 
from fileinput import filename

# Native HCP auth settings.
#HCP_TOKEN = os.environ['AWS_ACCESS_KEY_ID']
HCP_TOKEN = "Authorization: HCP usernamebase64:passwordmd5" #TODO: move this out to the os.environment
HCP_TENANT_URL = "https://namespace.tenant.domain/rest/"
DEBUG = True #Set to True for addition logging on the console.

def main():
    now = datetime.now()
    hostname = socket.gethostname()
    filename = now.strftime("%Y%m%d%H%M%S") + "-pgdump-" + hostname
    fullpath = "/tmp/" + filename
    postgrescommand = "pg_dumpall >" + fullpath 
    
    print "Backing up postgresql to HCP"
    try:
        ps = subprocess.Popen(postgrescommand, shell=True)
        output = ps.communicate()[0]
        if DEBUG:
            print output
            print now.strftime("%Y%m%d%H%M%S")
            print hostname 
            print "Uploading to HCP native..."
    except ValueError:
        print "There was an error running pg_dumpall" #Barf if an error occurs running pg_dumpall       
    #Check to see if pg_dumpall actually created a file
    try:
        isfilename = os.path.isfile(filename)
    except ValueError:
        print "Something went wrong, I can't find the pgdump file in /tmp. I expected one!"
        
    """
    Upload the backup file to an HCP tenant/namespace using the native HTTPS protocol.
    """
    try:
        filehandle = open(fullpath, 'rb')
        hcpurl = HCP_TENANT_URL + filename
        if DEBUG:
            print hcpurl 
        curl = pycurl.Curl()
        curl.setopt(pycurl.HTTPHEADER, [HCP_TOKEN])
        curl.setopt(pycurl.URL, hcpurl)
        curl.setopt(pycurl.SSL_VERIFYPEER, 0)
        curl.setopt(pycurl.SSL_VERIFYHOST, 0)
        curl.setopt(pycurl.UPLOAD, 1)
        curl.setopt(pycurl.INFILESIZE, os.path.getsize(fullpath))
        curl.setopt(pycurl.READFUNCTION, filehandle.read)
        curl.perform()
        if DEBUG: 
            print('Status: %d' % curl.getinfo(curl.RESPONSE_CODE))
            # Elapsed time for the transfer.
        if DEBUG:
            print('Status: %f' % curl.getinfo(curl.TOTAL_TIME))
            curl.close()
    except ValueError:
        print "Something went wrong contacting the HCP!"
if __name__ == '__main__':
    main()