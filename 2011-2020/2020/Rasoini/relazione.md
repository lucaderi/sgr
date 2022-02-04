# Detecting executable downloads with nDPI

Il progetto da me svolto per il corso di Gestione di Reti dell'a.a 2019/20 consiste nell'ampliare il software [nDPI](https://github.com/ntop/ndpi) aggiungendo al dissector HTTP la possibilità di riconoscere l'eventuale trasmissione di file eseguibile tramite due semplici euristiche:

* Controllo dell'header HTTP `Content-Type`

  Succede spesso che la trasmissione di file eseguibili sia accompagnata da un header `Content-Type` diverso dal generico `application/octet-stream`. Il dissector è stato dunque ampliato con la possibilità di riconoscere alcuni dei MIME type più comuni per i file eseguibili e in caso positivo flaggare il flow come `NDPI_BINARY_APPLICATION_TRANSFER` e si imposta la sua categoria a `NDPI_PROTOCOL_CATEGORY_DOWNLOAD_FT`.

* Controllo dell'header HTTP `Content-Disposition`

  Per il controllo su questo header, tipicamente usato per le comunicazioni via email, si va a controllare se l'estensione del filename contenuto all'interno del campo `filename` è l'estensione di un file eseguibile su Windows. In caso positivo si eseguono le stesse azioni descritte per l'header `Content-Type`.

## Ulteriori sviluppi

Purtroppo questi semplici controlli possono essere facilmenti aggirati fornendo un MIME type e/o un filename non sospetto.

Ulteriori sviluppi per questo genere di rilevamenti potrebbero essere il controllo dell'entropia del flusso per potere riconoscere il tipo di contenuto che è in trasmissione.

## Riferimenti

Le commit su cui si è svolto il lavoro sono:

* [0a4fbb8cfb7602c9c0b90e8329b56577dea207fd](https://github.com/ntop/nDPI/commit/0a4fbb8cfb7602c9c0b90e8329b56577dea207fd)
* [08f32f2e0ec5e05029c6849abec430caa570b7ea](https://github.com/ntop/nDPI/commit/08f32f2e0ec5e05029c6849abec430caa570b7ea)
* [baddfbb6c3d09398b207248c64dc8fe6d5568ee6](https://github.com/ntop/nDPI/commit/baddfbb6c3d09398b207248c64dc8fe6d5568ee6)
* [1edf5c49d662f7944ee976a63d54980a270a2419](https://github.com/ntop/nDPI/commit/1edf5c49d662f7944ee976a63d54980a270a2419)

