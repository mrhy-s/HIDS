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

