import struct


class DEXParse:
    """
    parse dex file
    @param : stream <dex file stream>
    """

    def __init__(self, stream):
        self.stream = stream

    def parse(self):
        return self.get_stringlist()

    def get_stringlist(self):
        header = self.get_header()

        string_ids_size = header['string_ids_size']
        string_ids_off = header['string_ids_off']

        strlist = []

        for i in range(string_ids_size):
            v = self.stream[string_ids_off+(i*4):string_ids_off+(i*4)+4]
            off = struct.unpack('<L', v)[0]
            c_size = ord(self.stream[off])
            c_char = self.stream[off+1:off+1+c_size]

            strlist.append(c_char)

        return strlist

    def get_header(self):
        string_ids_size = struct.unpack('<L', self.stream[0x38:0x3C])[0]
        string_ids_off = struct.unpack('<L', self.stream[0x3C:0x40])[0]

        header = {}
        header['string_ids_size'] = string_ids_size
        header['string_ids_off'] = string_ids_off

        return header

    def __del__(self):
        del self
