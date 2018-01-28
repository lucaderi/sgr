#! /bin/bash

# aggiorna il numero di pacchetti, richieste di update e withdraw, numero di pacchetti "invalid"

# parametri passatti
# VEDI CreaRRD.sh per la descrizione dei parametri

dir=$1
nPach=$2
nUpda=$3
nOpen=$4
nKeep=$5
nNoty=$6
nChan=$7
nTDum=$8
updReq=$9
witReq=$10
others=$11

rrdtool updatev ./webapps/AnalyzerBgp/Data/$dir/statistiche.rrd N:$nPach:$nUpda:$nOpen:$nKeep:$nNoty:$nChan:$nTDum:$updReq:$witReq:$others;

