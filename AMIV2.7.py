# -*- coding: utf-8 -*-
import libs.axmlprinter as axmlprinter

from libs.reader import APKReader
from libs.dexparse import DEXParse

from xml.etree.ElementTree import fromstring
from xml.dom import minidom
from optparse import OptionParser


import hashlib
import os
import sys
import re


class AMIVAnalysis:
    """
    AMIV Analysis class
    @param : filename <apk file>
    @param : outfile <txt file>
    """
    def __init__(self, filename, outfile):
        self.filename = filename
        self.outfile = outfile
        self.stream = open(filename, 'rb').read()
        self.reader = APKReader(filename).extract()
        self.report = {}

    def action(self):
        if False in self.is_android():
            print("Invaild APK file. AMIV aborted")

        self.parse_fileinfo()
        self.parse_manifest()
        self.parse_dexfile()

    def parse_fileinfo(self):
        """
        parse file basic information
        """
        self.report['fileinfo'] = {}
        self.report['fileinfo']['filename'] = os.path.basename(self.filename)
        self.report['fileinfo']['hash'] = {
            'md5': hashlib.md5(self.stream).hexdigest(),
            'sha1': hashlib.sha1(self.stream).hexdigest(),
            'sha256': hashlib.sha256(self.stream).hexdigest()
        }
        self.report['fileinfo']['filesize'] = os.path.getsize(self.filename)

    def parse_manifest(self):
        """
        parse apk file manifest information
        """

        self.report['manifest'] = {}

        printer = axmlprinter.AXMLPrinter(self.reader['AndroidManifest.xml'])
        buffer = minidom.parseString(printer.getBuff()).toxml()

        tree = fromstring(buffer)

        # get android package name
        self.report['manifest']['package'] = tree.get('package')

        # get permission list

        permissions = []

        for pack in tree.iter('uses-permission'):
            permissions.append(pack.attrib.values()[0])

        self.report['manifest']['permissions'] = permissions

        # get services

        services = []

        for pack in tree.iter('service'):
            services.append(pack.attrib.values()[0])

        self.report['manifest']['services'] = services

        # get receivers

        receivers = []

        for pack in tree.iter('receiver'):
            value = pack.attrib.values()
            i = 0  # value counter
            for i in range(0, len(value)):
                if not value[i].startswith('@') and \
                        not value[i].startswith("android.permission"):
                    receivers.append(value[i])
                    break

        self.report['manifest']['receivers'] = receivers

    def parse_dexfile(self):
        """
        parse dex file
        """
        self.report['strings'] = []

        d = DEXParse(self.reader['classes.dex'])
        strlist = d.parse()
        del d

        # regular expression list
        regexs = {
            'URL': r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
            'IP': r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
            'E-mail': r'\w+@\w+\.\w+'
        }

        for value in strlist:
            for key in regexs.keys():
                match = re.search(regexs[key], value)
                if match:
                    self.report['strings'].append({key: match.group()})

    def beautify(self):
        """
        beautify the report
        """
        msg = "=" * 42
        msg += "\n\nAndroid Malware Info Visibility [Ver 2.7] Report"
        msg += "\nBlog:http://geeklab.tistory.com/"
        msg += "\nE-mail:geeklab@naver.com"

        # file information
        msg += "\n\n=============File Information============="
        msg += "\n\nFilename : {0}".format(self.report['fileinfo']['filename'])
        msg += "\nMD5 : {0}".format(self.report['fileinfo']['hash']['md5'])
        msg += "\nSHA1 : {0}".format(self.report['fileinfo']['hash']['sha1'])
        msg += "\nSHA256 : {0}".format(self.report['fileinfo']['hash']['sha256'])
        msg += "\nFilesize: {0} bytes".format(self.report['fileinfo']['filesize'])

        # app manifest information
        msg += "\n\n=============APP Information============="
        msg += "\nPackage name : {0}".format(self.report['manifest']['package'])

        for permission in self.report['manifest']['permissions']:
            msg += "\nPermission : {0}".format(permission)

        for receiver in self.report['manifest']['receivers']:
            msg += "\nReceiver : {0}".format(receiver)

        for service in self.report['manifest']['services']:
            msg += "\nService : {0}".format(service)

        # interesting strings
        msg += "\n\n=============Interesting Strings============="

        for row in self.report['strings']:
            k, v = row.items()[0]
            msg += "\n{0} : {1}".format(k, v)

        msg += "\n"

        with open(self.outfile, 'w+') as f:
            f.write(msg)

        print(msg)

    def is_android(self):
        """
        check if it is android file
        """
        # apk file pattern
        patterns = [b'\xFE\xCA\x00\x00', b'AndroidManifest.xml',
                    b'resources.arsc', b'classes.dex']

        return [False for pattern in patterns if pattern not in self.stream]

    def __del__(self):
        del self


if __name__ == '__main__':
    parser = OptionParser(usage="%prog [-f] [-o]")
    parser.add_option('-f', '--file', dest="filename",
                      help="path of apk file",
                      metavar="FILE")
    parser.add_option('-o', '--outfile', dest="outfile",
                      help="path of report file",
                      metavar="FILE", default="AMIVReport.txt")

    # argument parse
    options, args = parser.parse_args()

    # if filename not found
    if options.filename is None:
        parser.print_help()  # print help
        sys.exit(2)

    a = AMIVAnalysis(options.filename, options.outfile)
    a.action()
    a.beautify()
    del a
