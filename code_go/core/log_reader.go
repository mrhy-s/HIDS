package core

import (
	"HIDS/core/utils"
	"fmt"
	"log"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Configuration fanotify
const (
	// Flags d'initialisation
	fanotifyInitFlags = unix.FAN_CLASS_PRE_CONTENT |
		unix.FAN_UNLIMITED_QUEUE |
		unix.FAN_UNLIMITED_MARKS

	// Flags d'ouverture des fichiers événements
	fanotifyEventFlags = unix.O_LARGEFILE | unix.O_RDONLY

	// Flags de marquage
	fanotifyMarkFlags = unix.FAN_MARK_ADD | unix.FAN_MARK_MOUNT

	// Événements surveillés
	fanotifyEvents = unix.FAN_OPEN |
		unix.FAN_MODIFY |
		unix.FAN_CLOSE_WRITE |
		unix.FAN_ACCESS

	// Taille du buffer de lecture
	eventBufferSize = 4096
)

// LogReader encapsule la logique de surveillance fanotify
type LogReader struct {
	fd   int
	path string
}

// CallLogReader point d'entrée principal
func CallLogReader(path string) {
	reader, err := NewLogReader(path)
	if err != nil {
		log.Fatalf("[FATAL] Impossible d'initialiser le log reader: %v", err)
	}
	defer reader.Close()

	if err := reader.Start(); err != nil {
		log.Fatalf("[FATAL] Erreur lors de la surveillance: %v", err)
	}
}

// NewLogReader crée et initialise un nouveau LogReader
func NewLogReader(path string) (*LogReader, error) {
	// Initialisation fanotify
	fd, err := unix.FanotifyInit(fanotifyInitFlags, fanotifyEventFlags)
	if err != nil {
		return nil, fmt.Errorf("échec FanotifyInit: %w", err)
	}

	utils.Println("[INFO] Fanotify initialisé avec succès. FD:", fd)

	reader := &LogReader{
		fd:   fd,
		path: path,
	}

	// Marquer le chemin à surveiller
	if err := reader.markPath(); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("échec du marquage du chemin: %w", err)
	}

	utils.Println("[INFO] Surveillance activée sur", path)

	return reader, nil
}

// markPath configure la surveillance du chemin
func (lr *LogReader) markPath() error {
	err := unix.FanotifyMark(
		lr.fd,
		fanotifyMarkFlags,
		fanotifyEvents,
		unix.AT_FDCWD,
		lr.path,
	)
	if err != nil {
		return fmt.Errorf("FanotifyMark a échoué pour %s: %w", lr.path, err)
	}
	return nil
}

// Start démarre la lecture des événements
func (lr *LogReader) Start() error {
	utils.Println("[INFO] Démarrage de la lecture des événements...")
	return lr.readEvents()
}

// readEvents boucle principale de lecture
func (lr *LogReader) readEvents() error {
	buf := make([]byte, eventBufferSize)

	for {
		n, err := unix.Read(lr.fd, buf)
		if err != nil {
			// Gérer EAGAIN (pas d'événement disponible en mode non-bloquant)
			if err == unix.EAGAIN {
				continue
			}
			return fmt.Errorf("erreur de lecture: %w", err)
		}

		if n > 0 {
			lr.processEvents(buf[:n])
		}
	}
}

// processEvents traite les événements reçus
func (lr *LogReader) processEvents(data []byte) {
	offset := 0
	for offset < len(data) {
		// Cast vers la structure fanotify_event_metadata
		metadata := (*unix.FanotifyEventMetadata)(unsafe.Pointer(&data[offset]))

		utils.Println(fmt.Sprintf(
			"[EVENT] Longueur: %d, Version: %d, Masque: 0x%x, FD: %d, PID: %d",
			metadata.Event_len,
			metadata.Vers,
			metadata.Mask,
			metadata.Fd,
			metadata.Pid,
		))

		// Fermer le FD de l'événement
		if metadata.Fd >= 0 {
			unix.Close(int(metadata.Fd))
		}

		// Avancer au prochain événement
		offset += int(metadata.Event_len)
	}
}

// Close libère les ressources
func (lr *LogReader) Close() error {
	if lr.fd > 0 {
		utils.Println("[INFO] Fermeture du file descriptor fanotify")
		if err := unix.Close(lr.fd); err != nil {
			return fmt.Errorf("erreur lors de la fermeture: %w", err)
		}
		lr.fd = -1
	}
	return nil
}
