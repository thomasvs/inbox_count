#!/usr/bin/env python
"""
inbox_count.py
 
inbox_count tells you how many email messages are in your inbox. 

http://feelslikeburning.com/projects/inbox_count/
"""
# Copyright 2009 Adam Wolf
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import sys, imaplib, getpass, logging
from optparse import OptionParser

def connect(host, port, username, password, ssl=True):
    """Connect and authenticate to IMAP4 server."""
    if ssl:
        logger.debug("Connecting to %s using SSL", host)
        server = imaplib.IMAP4_SSL(host, port)
    else:
        logger.debug("Connecting to %s without SSL", host)
        server = imaplib.IMAP4(host, port)
    logger.info("Logging in")
    server.login(username, password)
    return server

def parse_commandline_parameters():
    usage = """usage: %prog [options] [-u USERNAME -s HOST]

Logs into IMAP server HOST and displays the number of messages in USERNAME's inbox."""

    parser = OptionParser(usage)
    parser.add_option("-u", "--user", dest="username", help="Username to log into server")
    parser.add_option("--password", dest="password", default=False, help="Password to log into server.  If not included and password file not specified, password will be asked for interactively.")
    parser.add_option("-s", "--server", dest="host", help="Address of server")
    parser.add_option("-p", "--port", dest="port", default="993", help="Port of server, defaults to %default")
    parser.add_option("--password-file", dest="password_file", metavar="file", help="Read password from password file FILE")
    parser.add_option("--no-ssl", dest="ssl", action="store_false", default=True, help="Do not use SSL.")
    parser.add_option("--folder", dest="folder", action="store", default="INBOX", help="Folder to query")
    parser.add_option("--squash-threads", dest="squash_threads", action="store_true", default=False, help="Squash threads into a single mail (useful for GMail)")
    parser.add_option("-v", "--verbose", dest="verbose", action="store_true", default=False, help="Be verbose.")
    parser.add_option("--debug", dest="debug", action="store_true", default=False, help="Be really verbose.")

    options, args = parser.parse_args()
    
    if options.debug:
        logger.setLevel(logging.DEBUG)
    elif options.verbose:
        logger.setLevel(logging.INFO)
    
    if not options.host and not options.username:
        parser.error("Server host and username must be specified.")
    if not options.host:
        parser.error("Server host must be specified.")
    if not options.username:
        parser.error("Username must be specified.")
    
    try:
        options.port = int(options.port)
    except ValueError, e:
        parser.error("Port specified as %s. Port must be an integer." % options.port)

    if options.password_file and options.password:
        parser.error("Both password file and password specified.")
    elif options.password_file:
        logger.info("Password file specified: %s", options.password_file)
        options.password = parse_password_file(options.password_file)
    elif not options.password:
        logger.debug("No password specified.")
        options.password = getpass.getpass()

    return options, args

def get_inbox_count(server):
    """Returns the count of the server's INBOX"""
    return get_folder_count(server, 'INBOX')

def get_folder_count(server, folder, squash_threads=True):
    # FIXME: GMail stores threads per tag/folder, but does not support THREAD
    """Returns the count of the server's given folder"""
    status, count = server.select(folder, readonly=True)
    #this count includes DELETED messages!  Guess who didn't know that about IMAP...
    logger.debug("Server returned status: %s", status)
    logger.debug("Server returned count: %s", count)
    # this UNDELETED count applies only to the SELECTed folder
    status, message_numbers = server.search(None, 'UNDELETED')
    logger.debug("Server returned status: %s", status)
    logger.debug("Server returned UNDELETED message numbers: %s", message_numbers)
    undeleted = message_numbers[0].split()
    count = len(undeleted)

    if squash_threads:
        from email import parser

        subjects = {}

        for message in undeleted:
            data = server.fetch(message, '(BODY[HEADER])')
            header_data = data[1][0][1]
            p = parser.HeaderParser()
            msg = p.parsestr(header_data)
            # In-Reply-To and References can reference original mails that
            # you didn't receive, so not a good indicator
            # if 'In-Reply-To' in msg.keys() or 'References' in msg.keys():
            #     count -= 1
            subject = msg['Subject'].translate(None, '[]')
            strips = ['Re: ', 'RE: ', 'Fwd: ', 'FWD: ', 'FW: ']

            while True:
                stripped = False
                for strip in strips:
                    if subject.startswith(strip):
                        subject = subject[len(strip):]
                        stripped = True

                if not stripped:
                    break
            subjects[subject] = 1

        count = len(subjects.keys())

    return count

def parse_password_file(filename):
    f = open(filename, "r")
    password = f.readline().rstrip()
    f.close()
    return password

def get_config():
    logger.debug("Parsing command line parameters")
    options, args = parse_commandline_parameters()

    return options

def main():
    
    options = get_config()

    logging.info("Connecting to %s", options.host)
    imap_server = connect(options.host, 
            options.port, 
            options.username,
            options.password,
            ssl=options.ssl)
    
    logging.info("Getting folder count")
    inbox_count = get_folder_count(imap_server, options.folder, options.squash_threads)
    
    if options.verbose:
        logger.info("Number of emails in inbox: %d", inbox_count)

    print inbox_count
    return inbox_count

if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING,
            format="%(levelname)-8s %(message)s")
    logger = logging.getLogger()
    
    exit_code = main()
    sys.exit(exit_code)
