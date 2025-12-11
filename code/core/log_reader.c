#include <unistd.h>
#include <sys/fanotify.h>
#include <errno.h> // dépendance fanotify

int log_reader_init(void) {

    int fd;
    fd = fanotify_init(FAN_NONBLOCK);

    if (fd != 0) {
        return -1;
    }
    
    return 0;
}

void log_reader_add_file_monitoring(fd int) {
    int ret;
    
    char flags[512] = 
    "FAN_OPEN_EXEC | "            // Exécutions
    "FAN_MODIFY | "               // Modifications de contenu
    "FAN_ATTRIB | "               // Changements de permissions/propriété
    "FAN_CREATE | "               // Nouvelles créations
    "FAN_DELETE | "               // Suppressions
    "FAN_RENAME | "               // Renommages
    "FAN_CLOSE_WRITE | "          // Confirmations d'écriture
    "FAN_ONDIR | "                // Inclure les répertoires
    "FAN_EVENT_ON_CHILD";         // Surveiller les enfants directs

    ret = fanotify_mark(fd, flags)

    if (ret != 0) {
        return -1;
    }
    
    return 0;
}

void log_reader_remove_file_monitoring(void) {

}

void log_reader_choice_if_detected(void) {

}