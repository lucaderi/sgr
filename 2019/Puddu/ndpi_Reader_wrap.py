import sys
from ctypes import *

ndpi = CDLL('ndpiWrap.so')

#example: try -i <interface>

print('Number of arguments:', len(sys.argv), 'arguments.')
print('Argument List:', str(sys.argv))

length = len(sys.argv)

#crea un array di ctypes
arr = (c_char_p * length)()
arr[0] = './ndpiReader'.encode('utf-8')
for i in range(1, length):
    arr[i] = sys.argv[i].encode('utf-8')

ndpi.main(length, arr)
