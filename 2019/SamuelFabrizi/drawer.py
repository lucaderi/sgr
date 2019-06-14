import dash
import config
from dash.dependencies import Output, Input
import dash_core_components as dcc
import dash_html_components as html
import plotly.graph_objs as go
from threading import Thread
import numpy.random as nu


class Drawer(Thread):
    """
    classe che rappresenta il thread delegato alla comunicazione con un webserver per rappresentare
    il grafico ottenuto dalla struttura dati contenente le statistiche
    """

    def __init__(self, statistics):
        """
        :param statistics: struttura dati contenente le statistiche
        """
        Thread.__init__(self)

        self.mApp = dash.Dash(__name__)
        self.mStatistics = statistics

        # mColors lista di colori (rgb), un colore random per ogni applicazione
        self.mColors = []
        for _ in range(statistics.get_len()):
            random_color = (nu.randint(0, 255), nu.randint(0, 255), nu.randint(0, 255))
            self.mColors.append('rgb' + str(random_color))
            if config.DEBUG:
                print(str(random_color))

        # layout del grafico da visualizzare
        self.mApp.layout = html.Div([
            dcc.Interval(  # utilizzata per l'aggiornamento della pagina web
                id='interval-component',
                interval=config.TIME_REFRESH_GRAPH,  # millisecond
                n_intervals=0
            ),
            dcc.Graph(id='live-graph')  # grafico vero e proprio
        ])

        # registro la callback per l'aggiornamento del grafico specificando la funzione 'update_graph_live'
        self.mApp.callback(
            Output('live-graph', 'figure'),
            [Input('interval-component', 'n_intervals')])(self.update_graph_live)

    def update_graph_live(self, interval):
        """
        :param interval:    intervallo in cui è stata richiamata la
                            funzione (numero di aggiornamento) (solo a fini di DEBUG)
        :return: grafico aggiornato
        """
        # ottengo una copia della struttura dati delle statistiche
        dict_statistics = self.mStatistics.get_dict()

        trace = go.Bar(
            x=list(dict_statistics.keys()),
            y=list(dict_statistics.values()),
            marker=dict(color=self.mColors),
        )
        data = [trace]

        layout = go.Layout(
            title="Traffico",
            barmode='group'
        )

        figure = go.Figure(data=data, layout=layout)
        return figure

    def run(self):
        """
        ciclo di vita principale del thread drawer
        """
        self.mApp.run_server()
