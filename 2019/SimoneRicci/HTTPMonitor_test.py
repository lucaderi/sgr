import subprocess
import random

http_method = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'CONNECT', 'OPTIONS', 'TRACE']

def random_requests(host):
    n_reqs = random.randint(1, 5)
    null = open('/dev/null', 'w')
    for i in range(n_reqs):
        next_req = http_method[random.randint(0, len(http_method) - 1)]
        subprocess.call(['http', next_req, host], stdout=null)
    null.close()

def main():
    file = 'test_list.txt'
    f = open(file, 'r')
    host = f.readline()
    while host != '':
        host = host.strip()
        random_requests(host)
        host = f.readline()
    f.close()



if __name__ == '__main__':
    main()