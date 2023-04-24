from pytricia import PyTricia
from urllib.request import urlopen

pyt = PyTricia()

def webReader(page):
    webf = urlopen(page).read().decode('utf-8')
    return webf.split('\n')

def fileReader(file):
    idx = 0
    n_idx = 0
    f = open(file, "r+")
    addrArr = f.read().split()
    for i in addrArr:
        arr = webReader(i)
        for j in arr:
            if len(j) > 0:
                if j[0] == '#' or j[0] == '\0':
                    continue
                try:
                    ip = j
                    if'\r' in ip:
                        ip = ip[:-1]
                    pyt.insert(ip, '')
                    idx = idx + 1
                except ValueError as e:
                    n_idx = n_idx + 1
                    continue
    print(f'number of IP loaded: {idx}\nnumber of IP not loaded: {n_idx}')

def load_address(file_name):
    fileReader(file_name)
    return('Done')

def check_if_present(IP):
    return pyt.has_key(IP)
