

class Statistics:
    """
    classe che rappresenta la struttura dati contenente le statistiche
    calcolate, in un dato momento, dal programma
    """

    def __init__(self, apps_list):
        """
        :param apps_list: lista delle applicazioni
        """
        # dictStatistics dizionario con elementi del tipo (appname, n_bytes)
        self.dictStatistics = dict()
        self.list_appname = []
        self.len = 0

        # inizializzo il dizionario con i nomi delle applicazioni di cui classificare il traffico
        for app in apps_list:
            appname = app.get_appname()
            self.list_appname.append(appname)
            self.dictStatistics[appname] = 0
            self.len += 1

    def get_dict(self):
        """
        :return: copia del dizionario

        .. note::   non sono stati gestiti i vari aspetti di concorrenza considerando accettabili
                    eventuali errori di lettura dalla struttura dati condivisa
        """
        return self.dictStatistics.copy()

    def get_len(self):
        """
        :return: numero di elementi del dizionario (= numero di applicazioni)
        """
        return self.len

    def update(self, appname, n_bytes):
        """
        aggiorna le statistiche dell'applicazione appname aggiungendo n_bytes al totale

        :param appname: nome dell'applicazione
        :param n_bytes: numero di bytes da aggiungere
        """
        self.dictStatistics[appname] += n_bytes

    def print_statistics(self):
        """
        stampa il dizionario (solo a fini di debug)
        """
        print(str(self.dictStatistics))



