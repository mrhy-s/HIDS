package core

import (
	"HIDS/core/utils"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// Mode notification simple (pas de blocage)
	fanotifyInitFlags = unix.FAN_CLASS_NOTIF |
		unix.FAN_UNLIMITED_QUEUE |
		unix.FAN_UNLIMITED_MARKS

	fanotifyEventFlags = unix.O_RDONLY | unix.O_LARGEFILE

	// Surveillance du fichier spécifique
	fanotifyMarkFlags = unix.FAN_MARK_ADD

	// Événements pertinents pour un fichier de log
	fanotifyEvents = unix.FAN_MODIFY |
		unix.FAN_CLOSE_WRITE

	eventBufferSize = 4096
)

type LogReader struct {
	fd       int
	path     string
	realPath string // Chemin absolu résolu
}

func CallLogReader(path string) {
	utils.Println("[DEBUG] CallLogReader() - Path:", path)

	reader, err := NewLogReader(path)
	if err != nil {
		log.Fatalf("[FATAL] Impossible d'initialiser: %v", err)
	}
	defer reader.Close()

	if err := reader.Start(); err != nil {
		log.Fatalf("[FATAL] Erreur surveillance: %v", err)
	}
}

func NewLogReader(path string) (*LogReader, error) {

	// Résoudre le chemin absolu
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("résolution chemin: %w", err)
	}

	// Vérifier que le fichier existe
	if _, err := os.Stat(absPath); err != nil {
		return nil, fmt.Errorf("fichier inexistant %s: %w", absPath, err)
	}

	fd, err := unix.FanotifyInit(fanotifyInitFlags, fanotifyEventFlags)
	if err != nil {
		return nil, fmt.Errorf("FanotifyInit: %w (nécessite CAP_SYS_ADMIN)", err)
	}

	utils.Println("[INFO] Fanotify initialisé - FD:", fd)

	reader := &LogReader{
		fd:       fd,
		path:     path,
		realPath: absPath,
	}

	if err := reader.markPath(); err != nil {
		unix.Close(fd)
		return nil, err
	}

	utils.Println("[INFO] Surveillance active:", absPath)
	return reader, nil
}

func (lr *LogReader) markPath() error {
	err := unix.FanotifyMark(
		lr.fd,
		fanotifyMarkFlags,
		fanotifyEvents,
		unix.AT_FDCWD,
		lr.realPath,
	)
	if err != nil {
		return fmt.Errorf("FanotifyMark échoué pour %s: %w", lr.realPath, err)
	}
	return nil
}

func (lr *LogReader) Start() error {
	utils.Println("[INFO] Lecture événements...")
	return lr.readEvents()
}

func (lr *LogReader) readEvents() error {
	buf := make([]byte, eventBufferSize)

	for {
		n, err := unix.Read(lr.fd, buf)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return fmt.Errorf("erreur lecture: %w", err)
		}

		if n > 0 {
			lr.processEvents(buf[:n])
		}
	}
}

func (lr *LogReader) processEvents(data []byte) {
	offset := 0
	for offset < len(data) {
		metadata := (*unix.FanotifyEventMetadata)(unsafe.Pointer(&data[offset]))

		// Récupérer le chemin du fichier
		filePath := lr.getFilePath(metadata.Fd)

		eventType := lr.getEventType(metadata.Mask)

		utils.Println(fmt.Sprintf(
			"[EVENT] Type: %s | Fichier: %s | PID: %d | FD: %d",
			eventType,
			filePath,
			metadata.Pid,
			metadata.Fd,
		))

		// **Action utile** : Ici tu peux lire le contenu du fichier
		if metadata.Mask&unix.FAN_MODIFY != 0 {
			lr.handleModification(metadata.Fd)
		}

		// Toujours fermer le FD
		if metadata.Fd >= 0 {
			unix.Close(int(metadata.Fd))
		}

		offset += int(metadata.Event_len)
	}
}

// Récupérer le chemin du fichier depuis son FD
func (lr *LogReader) getFilePath(fd int32) string {
	if fd < 0 {
		return "N/A"
	}

	linkPath := fmt.Sprintf("/proc/self/fd/%d", fd)
	path, err := os.Readlink(linkPath)
	if err != nil {
		return "erreur-résolution"
	}
	return path
}

// Traduire le masque en texte
func (lr *LogReader) getEventType(mask uint64) string {
	switch {
	case mask&unix.FAN_MODIFY != 0:
		return "MODIFY"
	case mask&unix.FAN_CLOSE_WRITE != 0:
		return "CLOSE_WRITE"
	case mask&unix.FAN_OPEN != 0:
		return "OPEN"
	case mask&unix.FAN_ACCESS != 0:
		return "ACCESS"
	default:
		return fmt.Sprintf("UNKNOWN(0x%x)", mask)
	}
}

// Lire les nouvelles lignes ajoutées
func (lr *LogReader) handleModification(fd int32) {
	file := os.NewFile(uintptr(fd), "fanotify-event")
	if file == nil {
		return
	}
	defer file.Close()

	// Lire les dernières lignes (à adapter selon tes besoins)
	buf := make([]byte, 1024)
	n, err := file.Read(buf)
	if err != nil {
		utils.Println("[WARN] Lecture fichier:", err)
		return
	}

	utils.Println("[CONTENT]", string(buf[:n]))
}

func (lr *LogReader) Close() error {
	if lr.fd > 0 {
		utils.Println("[INFO] Fermeture fanotify")
		if err := unix.Close(lr.fd); err != nil {
			return fmt.Errorf("fermeture: %w", err)
		}
		lr.fd = -1
	}
	return nil
}
