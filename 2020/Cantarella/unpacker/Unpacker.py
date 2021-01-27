import struct


class Unpacker:
    'Class to unpack net streams into python integers'
    def unpackbufferint(self, buff, pointer, size):
        if size == 1:
            return struct.unpack('!B', buff[pointer:pointer + size])[0]
        if size == 2:
            return struct.unpack('!H', buff[pointer:pointer + size])[0]
        if size == 4:
            return struct.unpack('!I', buff[pointer:pointer + size])[0]
        else:
            print('Invalid integer size: %i' % size)
