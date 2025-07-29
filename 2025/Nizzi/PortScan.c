#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#define SCAN_DURATION 600  // 10 minuti

int main() {
    time_t start_time = time(NULL);
    time_t current_time;

    printf("[INFO] Avvio scansioni su 127.0.0.1 (porte 1-1024) per %d secondi...\n", SCAN_DURATION);

    srand(time(NULL));  // Inizializza il generatore di numeri casuali

    while (1) {
        current_time = time(NULL);
        if ((current_time - start_time) >= SCAN_DURATION) {
            printf("[INFO] Tempo scaduto. Terminazione scansioni.\n");
            break;
        }

        printf("[INFO] [%s] Avvio nuova scansione...\n", ctime(&current_time));

        // Esegue la scansione con nmap
        int ret = system("sudo nmap -p 1-1024 127.0.0.1 > /dev/null");
        if (ret == -1) {
            perror("[ERRORE] Impossibile eseguire nmap.");
            break;
        }

        // Pausa random tra 1 e 5 secondi
        int delay = (rand() % 5) + 1;
        printf("[INFO] Attesa di %d secondi prima della prossima scansione.\n", delay);
        sleep(delay);
    }

    return 0;
}
