#! /bin/bash

# crea l'archivio, viene aggiornato ogni 5 minuti (http://data.ris.ripe.net)

# nPach: numero pacchetti BGP sniffati
# nUpda: numero pacchetti Updaye sniffati
# nKeep: numero pacchetti Keep Alive sniffati

# updReq: numero di richieste di "update" contenute nei pacchetti BGP sniffati
# witReq: numero di richieste di "withdraw" contenute nei pacchetti BGP

# others: somma dei seguenti pacchetti
# nOpen: numero pacchetti Open sniffati
# nNoty: numero pacchetti Shut down and Peering sniffatti
# nChan: numero pacchetti change state sniffati
# nTDum: numero pacchetti table dump sniffati

dir=$1

rrdtool create ./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd -b N -s 300 \
DS:nPach:GAUGE:360:0:U \
DS:nUpda:GAUGE:360:0:U \
DS:nOpen:GAUGE:360:0:U \
DS:nKeep:GAUGE:360:0:U \
DS:nNoty:GAUGE:360:0:U \
DS:nChan:GAUGE:360:0:U \
DS:nTDum:GAUGE:360:0:U \
DS:updReq:GAUGE:360:0:U \
DS:witReq:GAUGE:360:0:U \
DS:others:GAUGE:360:0:U \
RRA:MAX:0.5:1:604800;

# storico di una settimana