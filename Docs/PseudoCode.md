hids/
├── hids/                         
│   ├── core/
│   │   ├── log_reader.c         # Lecteur de logs en temps réel
│   │   ├── event_parser.c       # Parseur d'événements
│   │   ├── event_queue.c        # File d'attente asynchrone
│   │   └── daemon.c             # Service daemon Linux
│   ├── detection/
│   │   ├── signature_engine.c   # Moteur de détection par signatures
│   │   ├── anomaly_detector.c   # Détection d'anomalies
│   │   └── correlator.c         # Corrélation d'événements
│   ├── config/
│   │   ├── config_loader.c      # Chargement fichiers .conf
│   │   ├── validators.c         # Validation des configs
│   │   └── defaults.c           # Valeurs par défaut
│   ├── storage/
│   │   ├── database.c           # Abstraction SQLite
│   │   ├── migrations.c         # Schéma base de données
│   │   └── queries.c            # Requêtes pré-optimisées
│   ├── output/
│   │   ├── alerter.c            # Génération d'alertes
│   │   ├── logger.c             # Logging interne
│   │   └── cli.c                # Interface CLI
│   └── utils/
│       ├── regex_cache.c        # Cache pour performances
│       └── helpers.c            # Fonctions utilitaires
├── conf/                        # Fichiers de configuration
│   ├── hids.conf                # Config principale
│   ├── signatures.conf          # Règles de détection
│   ├── anomalies.conf           # Seuils anomalies
│   └── correlation.conf         # Règles de corrélation
├── data/                        # Données locales
│   ├── hids.db                  # Base SQLite
│   ├── baseline.json            # Profils comportement
│   └── logs/                    # Logs internes
├── bin/
│   └── hids                     # Script principal/CLI
├── install.sh                   # Installation Linux
└── README.md



## log_reader.c :

FONCTION init {
    Allocation et remise a 0 de la mémoire
    Lancement de fanotify avec le mode non bloquant (FAN_NONBLOCK)
    Chargement du fichier de configuration qui contient tous les logs à surveiller
}

FONCTION addFileToSpec {
    gestion erreur : mauvais chemin
    ouvrir fichier 
    aller a la fin du fichier (et log la position de la dernière lecture)

    initialise la surveillance via fanotify
}

FONCTION choiceIfDetected {
    charge les règles
    gestion erreur : fichier n'existe pas / syntaxe invalide
}