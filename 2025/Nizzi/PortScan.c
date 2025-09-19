#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>

#define SCAN_DURATION 600  // 10 minuti

int main() {
    char target_ip[64];
    char choice;

    printf("[INFO] Vuoi fare il port scan su localhost (127.0.0.1)? (s/n): ");
    scanf(" %c", &choice);

    if (choice == 's' || choice == 'S') {
        strcpy(target_ip, "127.0.0.1");
    } else {
        printf("[INFO] Inserisci l'IP del target: ");
        scanf("%63s", target_ip);  // 63 caratteri + terminatore
    }

    time_t start_time = time(NULL);
    time_t current_time;

    printf("[INFO] Avvio scansioni su %s (porte 1-1024) per %d secondi...\n", target_ip, SCAN_DURATION);

    srand(time(NULL));  // Inizializza il generatore di numeri casuali

    while (1) {
        current_time = time(NULL);
        if ((current_time - start_time) >= SCAN_DURATION) {
            printf("[INFO] Tempo scaduto. Terminazione scansioni.\n");
            break;
        }

        printf("%s [INFO] Avvio nuova scansione...\n", ctime(&current_time));

        // Esegue la scansione con nmap
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "sudo nmap -p 1-1024 %s > /dev/null", target_ip);
        int ret = system(cmd);
        
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
