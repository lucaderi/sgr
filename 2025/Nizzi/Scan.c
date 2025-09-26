#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>  // inet_pton

#define SCAN_DURATION 600  // 10 minuti

int main() {
    char target_ip[64];
    char choice;
    struct in_addr addr;

    printf("[INFO] Vuoi fare il port scan su localhost (127.0.0.1)? (s/n): ");
    if (scanf(" %c", &choice) != 1) {
        fprintf(stderr, "[ERRORE] Input non valido.\n");
        return 1;
    }

    if (choice == 's' || choice == 'S') {
        strcpy(target_ip, "127.0.0.1");
    } else {
        // Ciclo finché l'utente non inserisce un IPv4 valido
        while (1) {
            printf("[INFO] Inserisci l'IP del target: ");

            if (fgets(target_ip, sizeof(target_ip), stdin) == NULL) {
                fprintf(stderr, "[ERRORE] Lettura fallita. Riprova.\n");
                continue;
            }
    
            // Rimuovo newline finale
            target_ip[strcspn(target_ip, "\n")] = '\0';
    
            if (target_ip[0] == '\0') {
                printf("[ERRORE] Nessun input rilevato. Riprova.\n");
                continue;
            }

            // Verifico che sia un IPv4 numerico valido
            if (inet_pton(AF_INET, target_ip, &addr) == 1) {
                break; // IP valido
            } else {
                printf("[ERRORE] L'indirizzo '%s' non è un IPv4 valido. Riprova.\n", target_ip);
            }
        }
    }

    time_t start_time = time(NULL);
    time_t current_time;

    printf("[INFO] Avvio scansioni su %s (porte 1-1024) per %d secondi...\n", target_ip, SCAN_DURATION);

    srand(time(NULL));  // Inizializzo il generatore di numeri casuali

    while (1) {
        current_time = time(NULL);
        if ((current_time - start_time) >= SCAN_DURATION) {
            printf("[INFO] Tempo scaduto. Terminazione scansioni.\n");
            break;
        }

        printf("%s [INFO] Avvio nuova scansione...\n", ctime(&current_time));

        // Eseguo la scansione con nmap
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "sudo nmap -p 1-1024 %s > /dev/null", target_ip);
        int ret = system(cmd);
        
        if (ret == -1) {
            perror("[ERRORE] Impossibile eseguire nmap.");
            break;
        }

        // Pausa random tra 1 e 30 secondi
        int delay = (rand() % 30) + 1;
        printf("[INFO] Attesa di %d secondi prima della prossima scansione.\n", delay);
        sleep(delay);
    }

    return 0;
}
