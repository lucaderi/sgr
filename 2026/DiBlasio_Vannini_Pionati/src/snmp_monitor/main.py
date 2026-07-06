import argparse # Permette di leggere gli argomenti da linea di comando
import asyncio
import contextlib #serve per chiudere pulitamente il task che gestisce le trap.
import logging
import signal # Serve per intercettare segnali di terminazione (CTRL + C)
 
from snmp_monitor.config import leggi_config
from snmp_monitor.csv_writer import write_csv
from snmp_monitor.models import TrapEvent
from snmp_monitor.poller import poll_all_agents
from snmp_monitor.trap_reciever import (avvia_in_background, trap_richiede_polling)
from snmp_monitor.rdd_module.rdd_manager import run_manager
from snmp_monitor.rdd_module.rdd_grapher import generate_all_graph
 
logger = logging.getLogger(__name__)

async def exec_polling(config_path: str, output_path: str, interval: int, stop_event: asyncio.Event):
    """
    Esegue il polling di tutti gli agenti, scrive le metriche lette nel file CSV e ripete il ciclo `time` secondi
    Gli agenti vengono ricaricati dal file di configurazione ad ogni ciclo,
    cosi' eventuali modifiche al YAML (aggiunta/rimozione di un agente)
    vengono applicate senza dover riavviare il processo.
    """
    
    while not stop_event.is_set():
        
        # Salva l'inizio del ciclo. Per sapere quanto è durato il polling.
        ciclo_iniziato = asyncio.get_event_loop().time()
        
        # Legge i file YAML
        try:
            agents = leggi_config(config_path)
        except Exception as exc:
            logger.error("Impossibile leggere la configurazione %s: %s", config_path, exc)
            await sleep_until_next_cycle(interval, ciclo_iniziato, stop_event)
            continue
        
        # Se agents è vuoto non esegue il polling
        if not agents:
            logger.warning("Nessun agente configurato in %s, ciclo saltato", config_path)
            await sleep_until_next_cycle(interval, ciclo_iniziato, stop_event)
            continue
        
        
        try:
            # Esegue il polling degli agenti
            metrics = await poll_all_agents(agents)
            logger.info("Polling completato: %d metriche raccolte da %d agenti",
                        len(metrics), len(agents))
 
            if metrics:
                # Scrittura su file in un thread separato
                await asyncio.to_thread(write_csv, metrics, output_path)
 
        except Exception as exc:
            logger.exception("Errore nel ciclo di polling: %s", exc)
 
        await sleep_until_next_cycle(interval, ciclo_iniziato, stop_event)
 
    logger.info("Loop di polling terminato")

async def sleep_until_next_cycle(interval: int, ciclo_iniziato: float, stop_event: asyncio.Event,) -> None:
    """
    Calcola quanto tempo resta prima del prossimo ciclo, sottraendo il tempo
    gia' speso nel ciclo corrente (polling + scrittura), cosi' l'intervallo
    tra l'inizio di un ciclo e l'inizio del successivo resta costante
    invece di accumulare ritardo ciclo dopo ciclo.
 
    Si interrompe immediatamente se stop_event viene impostato, invece di
    aspettare la fine del sleep.
    """
    tempo_trascorso = asyncio.get_event_loop().time() - ciclo_iniziato
    tempo_residuo = max(0.0, interval - tempo_trascorso)
 
    if tempo_trascorso > interval:
        logger.warning(
            "Il ciclo di polling ha impiegato %.1fs, piu' dell'intervallo configurato (%ds)",
            tempo_trascorso, interval,
        )
 
    try:
        await asyncio.wait_for(stop_event.wait(), timeout=tempo_residuo)
    except asyncio.TimeoutError:
        pass  # timeout raggiunto normalmente: si procede al ciclo successivo

def signal_handlers(stop_event: asyncio.Event) -> None:
    """
    Intercetta SIGINT/SIGTERM per uno shutdown pulito invece di un
    KeyboardInterrupt non gestito a meta' di un ciclo di polling.
    """
    
    # Recupera l'operazione che sta eseguendo
    loop = asyncio.get_running_loop() 

    # Viene eseguita quando arriverà un segnale
    def _handle_signal() -> None:
        logger.info("Segnale di stop ricevuto, chiusura in corso...")
        try:
            run_manager() #legge metrics.csv
            generate_all_graph()#genera il grafo
        except Exception as e:
            logger.error(f"Errore durante la generazione grafici: {e}")
        finally:
            stop_event.set() # stop_event diventa True e termina il ciclo a riga 20
    
    # SIGINT è il segnale che invio da riga di comando
    # SIGTERM è quello inviato dal S.O per terminare un processo
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            # Quando riceve un segnale esegue _handle_signal
            loop.add_signal_handler(sig, _handle_signal)
        except NotImplementedError:
            pass

async def gestisci_trap_polling(
    trap_queue: asyncio.Queue[TrapEvent],
    config_path: str,
    output_path: str,
) -> None:
    """
    Gestisce le trap ricevute dal trap receiver.

    Questa funzione è separata da exec_polling():
    - exec_polling() continua a fare il polling periodico;
    - questa funzione fa solo il polling immediato causato da trap rilevanti.

    In questo modo non modifichiamo la logica già scritta da altri.
    """

    while True:
        trap = await trap_queue.get()

        try:
            logger.info(
                "Trap ricevuta dal main: tipo=%s sorgente=%s",
                trap.trap_type,
                trap.source_ip,
            )

            # Non tutte le trap devono attivare un polling immediato.
            # Per esempio authenticationFailure viene registrata,
            # ma non è detto che richieda polling delle interfacce.
            if not trap_richiede_polling(trap):
                logger.info(
                    "Trap %s registrata ma non usata per polling immediato",
                    trap.trap_type,
                )
                continue

            logger.info(
                "Trap %s rilevante: avvio polling immediato",
                trap.trap_type,
            )

            try:
                agents = leggi_config(config_path)

            except Exception as exc:
                logger.error(
                    "Impossibile leggere la configurazione %s dopo trap %s: %s",
                    config_path,
                    trap.trap_type,
                    exc,
                )
                continue

            if not agents:
                logger.warning(
                    "Nessun agente configurato in %s, polling da trap saltato",
                    config_path,
                )
                continue

            try:
                metrics = await poll_all_agents(agents)

                logger.info(
                    "Polling immediato da trap %s completato: %d metriche raccolte",
                    trap.trap_type,
                    len(metrics),
                )

                if metrics:
                    await asyncio.to_thread(write_csv, metrics, output_path)

            except Exception as exc:
                logger.exception(
                    "Errore durante il polling immediato da trap %s: %s",
                    trap.trap_type,
                    exc,
                )

        finally:
            trap_queue.task_done()
 
async def main_async(args: argparse.Namespace) -> None:
    """
    Questa funzione gestisce tutto ciò che serve per avviare il ciclo principale
    Il polling periodico resta gestito da exec_polling().
    In più, il main avvia il trap receiver in background e gestisce
    le trap rilevanti tramite una queue asincrona.
    """
    
    # È la variabile che gestisce la fine del programma
    stop_event = asyncio.Event()
    signal_handlers(stop_event)

    #Queue usata per trasferire le trap dal thread del trap_receiver
    #al ciclo asyncio del main.
    trap_queue: asyncio.Queue[TrapEvent] = asyncio.Queue()

    #Recupero il loop asyncio principale.
    #La callback on_trap verrà chiamata da un thread separato,
    #quindi l'inserimento nella queue deve essere thread-safe.
    loop = asyncio.get_running_loop()

    def on_trap(trap: TrapEvent) -> None:
        """
        Callback chiamata dal trap receiver quando arriva una trap.

        Non fa polling direttamente, perché viene eseguita nel thread
        del trap receiver. Si limita a passare la trap al main.
        """

        loop.call_soon_threadsafe(trap_queue.put_nowait, trap)

    #Avvia il trap receiver in background.
    #Il receiver resta in ascolto mentre exec_polling continua
    #a fare il polling periodico.
    avvia_in_background(
        host=args.trap_host,
        port=args.trap_port,
        community=args.trap_community,
        on_trap=on_trap,
    )

    logger.info(
        "Trap receiver avviato su udp://%s:%s",
        args.trap_host,
        args.trap_port,
    )

    # Task separato che gestisce solo le trap.
    trap_task = asyncio.create_task(
        gestisci_trap_polling(
            trap_queue=trap_queue,
            config_path=args.config,
            output_path=args.output,
        )
    )

    try:
        # Passa: il file YAML da leggere, il CSV per salvare le metriche, l'intervallo e stop_event
        await exec_polling(
            config_path=args.config,
            output_path=args.output,
            interval=args.interval,
            stop_event=stop_event,
        )
    finally:
        # Quando il main termina, fermiamo anche il task delle trap.
        trap_task.cancel()

        with contextlib.suppress(asyncio.CancelledError):
            await trap_task


def main() -> None:
    parser = argparse.ArgumentParser(description="SNMP Poller")
    parser.add_argument(
        # Specifica gli Agents
        "--config", default="agents.yml",
        help="Percorso del file YAML di configurazione degli agenti",
    )
    parser.add_argument(
        # Su quale file scrivere
        "--output", default="metrics.csv",
        help="Percorso del file CSV di output",
    )
    parser.add_argument(
        # L'intervallo di polling
        "--interval", type=int, default=30,
        help="Intervallo in secondi tra un ciclo di polling e il successivo",
    )
    parser.add_argument(
    "--trap-host",
    default="127.0.0.1",
    help="Indirizzo locale su cui il trap receiver resta in ascolto",
    )

    parser.add_argument(
        "--trap-port",
        type=int,
        default=9162,
        help="Porta UDP su cui ricevere le trap SNMP",
    )

    parser.add_argument(
        "--trap-community",
        default="public",
        help="Community SNMPv1/v2c accettata dal trap receiver",
    )
    
    args = parser.parse_args()
    
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )

    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        logger.info("Interruzione da tastiera, chiusura in corso...")
 

# Quando esegue questo file chiamerà la funzione main
if __name__ == "__main__":
    main()
 
