package main

import (
	"HIDS/config"
	"HIDS/core"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	configPath := flag.String("config", "/etc/hids/hids.yaml", "Chemin du fichier de configuration")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Configuration invalide : %v", err)
	}

	hids, err := core.NewHIDS(cfg)
	if err != nil {
		log.Fatalf("Initialisation HIDS : %v", err)
	}

	if err := hids.Start(); err != nil {
		log.Fatalf("Démarrage HIDS: %v", err)
	}

	// Gestion d'arrêt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Arrêt en cours...")
	hids.Stop()
}
