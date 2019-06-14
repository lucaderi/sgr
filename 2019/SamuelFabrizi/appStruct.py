import os
import config


def open_file2read(path):
    """
    :param path: path del file da aprire in lettura
    :return: file aperto in lettura
    :raise ValueError: lanciata se si verificano errori nell'apertura del file
    """
    if not os.path.exists(path):
        raise ValueError("ERROR: " + path + " non esiste")
    f = open(path, "r")
    return f


class AppStruct:
    """
    classe che descrive i metadati di un'applicazione. Contiene funzioni ed attributi di utilità per una gestione
    più ordinata del file contenente gli indirizzi ip di una certa applicazione
    """

    def __init__(self, path):
        """
        :param path: path del file contenente gli indirizzi ip dell'applicazione
        """
        occ = path.rfind('/') + 1
        appname = path[occ:].split('_')[0]
        # mAppName nome dell'applicazione
        self.mAppName = appname
        # mPath path del file relativo all'applicazione appname
        self.mPath = config.DIR_FILES_APP + path

    def read_ip_app(self, rtree):
        """
        :param rtree: radix tree che contiene gli indirizzi ip con cui fare matching
        :except ValueError: eccezione lanciata nel caso di errori in apertura del file
        """
        try:
            f = open_file2read(self.mPath)
        except ValueError:
            raise

        # ogni riga contiene un indirizzo ip quindi salvo ogni riga nel radix tree
        lines_r = f.readlines()
        for line in lines_r:
            rnode = rtree.add(line.translate({ord(i): None for i in ' \t\n\r'}))
            rnode.data["app"] = self.mAppName

        f.close()

    def get_appname(self):
        """
        :return: nome dell'applicazione
        """
        return self.mAppName

    def get_path(self):
        """
        :return: path del file contenente gli indirizzi ip dell'applicazione
        """
        return self.mPath
