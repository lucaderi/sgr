# Progetto Gestione di Reti
Il progetto ha lo scopo di utilizzare l' API di ntopng per analizzare il traffico riguardante i social network all'interno della rete. Gli script messi a disposizione mostrano statistiche che riguardano pacchetti, bytes e durata dei flussi social di un determinato host.
# Requisiti
-ntopng
# Uso
- Copiare ~/[nomeprogetto]/lua/* in ~/ntopng/scripts/lua
- Copiare i file ~/[nomeprogetto]/css/* in ~/ntopng/httpdocs/css
- Copiare i file ~/[nomeprogetto]/js/* in ~/ntopng/httpdocs/js
- Eseguire ntopng e visitare la pagina web in Hosts->Hosts->[Seleziona un ip]->Tab Social
# NB
- Il tab Social, sopra citato, sarà visibile solo se vengono rilevati flussi con categoria SocialNetwork.
