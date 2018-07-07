# Progetto Gestione di Rete
Il progetto ha lo scopo di utilizzare l' API di ntopng per analizzare i flussi riguardanti i social network all'interno della rete. Gli script messi a disposizione mostrano statistiche che riguardano pacchetti, bytes e durata dei flussi social di un determinato host.
# Requisiti
-ntopng
# Uso
- Copiare ~/Armato_Russo/lua/* in ~/ntopng/scripts/lua
- Copiare i file ~/Armato_Russo/js/* in ~/ntopng/httpdocs/js
- [EMBED MODE] Eseguire ntopng e visitare la pagina web in Hosts->Hosts->[Seleziona un ip]->Tab Social
- [NON-EMBED MODE] Eseguire ntopng e visitare la pagina web [host:port]/lua/host_social_details.lua?host=[ip]
# N.B.
- Il Tab Social sarà visibile solo se vengono rilevati flussi con categoria SocialNetwork
