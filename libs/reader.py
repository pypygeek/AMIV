from zipfile import ZipFile, is_zipfile

import sys
import traceback
import json


# exception handler
def handle_exception(func):
    def wrapper(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
            return result
        except:
            print(traceback.format_exc())
            return None
    return wrapper


class APKReader:
    """
    apk file reader based on filename
    @param : filename <apk file path>
    """
    def __init__(self, filename):
        self.filename = filename
        # check if it is valid zipfile
        if not is_zipfile(filename):
            print("Invalid ZIP file. program aborted")
            sys.exit(2)

        self.extract()

    @handle_exception
    def extract(self):
        z = ZipFile(self.filename)
        report = {}

        report['AndroidManifest.xml'] = z.read('AndroidManifest.xml')
        report['classes.dex'] = z.read('classes.dex')

        return report

    def __del__(self):
        del self
