#include <unistd.h>
#include <sys/fanotify.h>
#include <errno.h>         // dépendance fanotify
#include <stdint.h>        // dépendance pour uint64_t
#include <stdio.h>         // dépendance pour sprintf

int log_reader_init(void) {
    int fd;

    uint64_t init_flags =
        FAN_CLASS_NOTIF |             // notifications uniquement (pas de blocage)
        FAN_NONBLOCK |                // mode non-bloquant
        FAN_UNLIMITED_QUEUE |         // pas de limite de taille de file d'attente
        FAN_UNLIMITED_MARKS;          // pas de limite de marques

    uint64_t init_flags = O_RDONLY | O_LARGEFILE; 

    fd = fanotify_init(init_flags, event_flags);

    if (fd == -1) {
        perror("Error : fanotify_init");
        return -1;
    }

    char buffer[100];
    int len = snprintf(buffer, sizeof(buffer), "[+] fanotify initialized with fd=%d\n", fd);
    write(STDOUT_FILENO, buffer, len);
    
    return fd;
}

void log_reader_add_file_monitoring(int fd, const char *path) {
    int ret;
    
    uint64_t flags = 
        FAN_OPEN_EXEC |            // Exécutions
        FAN_MODIFY |               // Modifications de contenu
        FAN_ATTRIB |               // Changements métadonnées
        FAN_CREATE |               // Créations
        FAN_DELETE |               // Suppressions
        FAN_MOVED_FROM |           // Renommages (source)
        FAN_MOVED_TO |             // Renommages (destination)
        FAN_CLOSE_WRITE |          // Fermeture après écriture
        FAN_ONDIR |                // Inclure les répertoires
        FAN_EVENT_ON_CHILD;        // Événements sur enfants

    ret = fanotify_mark(fd, FAN_MARK_ADD, flags, AT_FDCWD, path);

    if (fd != 0) {
        perror("Error : fanotify_mark");
        return;
    }

    char buffer[100];
    int len = snprintf(buffer, sizeof(buffer), "[+] Surveillance ajoutée sur : %s\n", path);
    write(STDOUT_FILENO, buffer, len);
    
    return;
}

void log_reader_remove_file_monitoring(void) {

}

void log_reader_choice_if_detected(void) {

}