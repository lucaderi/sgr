# encoding=utf8
# autore: Alessandro Di Giorgio
# mail: a.digiorgio1@studenti.unipi.it

import docker

enabled = False # se True raccoglie info sui container
host = docker.from_env()

#cerca il container a cui appartiene il pid
def getContainerByPid(pid):
    try:
        for c in host.containers.list():
            if c.attrs['State']['Pid'] == pid:
                return c
        return None
    except Exception:
        return None
