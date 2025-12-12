# Guide HIDS en C avec fanotify — Partie 3 : Configuration et Sécurité du Code

## Table des matières
1. [Système de fichiers de configuration](#1-système-de-fichiers-de-configuration)
2. [Niveaux de sécurité et modes de réponse](#2-niveaux-de-sécurité-et-modes-de-réponse)
3. [Sécurisation du code C](#3-sécurisation-du-code-c)
4. [Abandon de privilèges](#4-abandon-de-privilèges)
5. [Sandboxing avec seccomp](#5-sandboxing-avec-seccomp)

---

## 1. Système de fichiers de configuration

### 1.1 Choix du format de configuration

Plusieurs options sont possibles pour le format des fichiers de configuration :

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ FORMAT        │ AVANTAGES                    │ INCONVÉNIENTS                 │
├─────────────────────────────────────────────────────────────────────────────┤
│ Texte plat    │ Simple à parser manuellement │ Pas de structure hiérarchique │
│ (clé=valeur)  │ Pas de dépendance            │ Difficile pour config complexe│
├─────────────────────────────────────────────────────────────────────────────┤
│ INI           │ Simple, hiérarchie basique   │ Pas de types de données      │
│               │ inih (header-only)           │ Limité pour listes complexes │
├─────────────────────────────────────────────────────────────────────────────┤
│ JSON          │ Standard universel           │ Pas de commentaires natifs    │
│               │ Structures imbriquées        │ Verbeux pour config simple   │
│               │ cJSON (header-only)          │                              │
├─────────────────────────────────────────────────────────────────────────────┤
│ libconfig     │ Syntaxe lisible (C-like)     │ Dépendance externe           │
│               │ Types forts                  │ Moins connu que JSON/YAML    │
│               │ Commentaires supportés       │                              │
│               │ Hiérarchie complète          │                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Recommandation pour un HIDS : libconfig**

Raisons :
- Syntaxe claire et lisible par un humain (important pour audit)
- Support natif des commentaires (documentation in-place)
- Types de données appropriés (entiers, booléens, listes)
- Validation syntaxique intégrée avec messages d'erreur précis

### 1.2 Structure des fichiers de configuration

Organisation recommandée :

```
/etc/hids/
├── hids.conf           # Configuration principale
├── whitelist.conf      # Règles whitelist
├── blacklist.conf      # Règles blacklist  
├── alerts.conf         # Configuration des alertes
└── rules.d/            # Règles additionnelles (modulaires)
    ├── 00-base.conf
    ├── 10-ssh.conf
    ├── 20-web.conf
    └── 99-custom.conf
```

### 1.3 Configuration principale détaillée

```c
/* /etc/hids/hids.conf - Exemple commenté */

/*
 * Configuration principale du HIDS
 * Format : libconfig
 * Documentation : voir hids.conf(5)
 */

/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
/*                           SECTION GLOBALE                                  */
/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */

global = {
    /*
     * Niveau de sécurité global (0-10)
     * 
     * 0-2 : Mode apprentissage (log everything, block nothing)
     * 3-5 : Mode standard (log + alert on suspicious)
     * 6-8 : Mode renforcé (block unknown processes on critical files)
     * 9-10: Mode paranoïaque (default deny)
     */
    security_level = 5;
    
    /*
     * Mode de fonctionnement
     * - "monitor" : Log uniquement, ne bloque jamais
     * - "enforce" : Applique les règles (peut bloquer)
     */
    mode = "enforce";
    
    /*
     * Comportement par défaut pour les accès non catégorisés
     * - "allow" : Autoriser si non blacklisté
     * - "deny"  : Refuser si non whitelisté (recommandé niveau 6+)
     */
    default_action = "allow";
    
    /*
     * Utilisateur sous lequel le daemon tourne après initialisation
     * Le daemon démarre en root, initialise fanotify, puis drop les privilèges
     */
    run_as_user = "hids";
    run_as_group = "hids";
    
    /* PID file pour la gestion du daemon */
    pid_file = "/var/run/hids/hids.pid";
};

/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
/*                         SECTION SURVEILLANCE                               */
/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */

monitoring = {
    /*
     * Points de montage à surveiller
     * Utilise FAN_MARK_MOUNT pour chaque entrée
     */
    mount_points = ["/"];
    
    /*
     * Événements fanotify à capturer
     * Valeurs possibles :
     * - "open_perm"      : Demande d'ouverture (bloquant)
     * - "access_perm"    : Demande de lecture (bloquant)
     * - "open_exec_perm" : Demande d'exécution (bloquant, Linux 5.0+)
     * - "close_write"    : Fichier fermé après écriture (non-bloquant)
     * - "modify"         : Fichier modifié (non-bloquant)
     */
    events = ["open_perm", "close_write", "open_exec_perm"];
    
    /*
     * Chemins à exclure complètement de la surveillance
     * Ces chemins ne génèrent AUCUN événement
     * Utile pour réduire le bruit (ex: /proc, /sys)
     */
    exclude_paths = [
        "/proc/",
        "/sys/",
        "/dev/",
        "/run/",
        "/tmp/",
        "/var/cache/"
    ];
    
    /*
     * Taille du buffer de lecture fanotify (en bytes)
     * Valeur recommandée : 4096 minimum, 65536 pour haute charge
     */
    buffer_size = 65536;
    
    /*
     * Timeout pour répondre aux permission events (en ms)
     * Si dépassé, l'accès est autorisé par défaut (fail-open)
     */
    permission_timeout_ms = 5000;
};

/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
/*                            SECTION LOGGING                                 */
/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */

logging = {
    /*
     * Destination des logs
     * - "syslog" : Via syslog (recommandé pour production)
     * - "file"   : Fichier dédié
     * - "both"   : Les deux
     */
    destination = "both";
    
    /* Configuration syslog */
    syslog = {
        facility = "daemon";  /* local0-local7, daemon, auth, etc. */
        ident = "hids";       /* Identifiant dans les logs */
    };
    
    /* Configuration fichier */
    file = {
        path = "/var/log/hids/hids.log";
        max_size_mb = 100;    /* Rotation automatique */
        max_files = 10;       /* Nombre de fichiers à conserver */
    };
    
    /*
     * Niveau de verbosité
     * - "error"   : Erreurs uniquement
     * - "warning" : + Avertissements
     * - "info"    : + Informations générales
     * - "debug"   : + Détails de debug (ATTENTION: très verbeux)
     */
    level = "info";
    
    /*
     * Format des logs
     * Variables disponibles :
     * %T - Timestamp ISO 8601
     * %L - Niveau (ERROR, WARNING, INFO, DEBUG)
     * %P - PID du processus concerné
     * %E - Exécutable du processus
     * %F - Fichier accédé
     * %A - Action (ALLOW, DENY, LOG)
     * %R - Raison
     */
    format = "%T [%L] PID=%P EXE=%E FILE=%F ACTION=%A REASON=%R";
};

/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
/*                           SECTION PERFORMANCE                              */
/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */

performance = {
    /*
     * Nombre de threads worker pour traiter les événements
     * Recommandation : nombre de cœurs CPU
     */
    worker_threads = 4;
    
    /*
     * Taille de la queue interne entre reader et workers
     * En nombre d'événements
     */
    event_queue_size = 10000;
    
    /*
     * Utiliser les queues/marks illimitées ?
     * Nécessite CAP_SYS_ADMIN
     * Recommandé en production pour éviter les pertes d'événements
     */
    unlimited_queue = true;
    unlimited_marks = true;
};

/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
/*                    SECTION FICHIERS DE RÈGLES                              */
/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */

rules = {
    /* Fichiers de listes */
    whitelist_file = "/etc/hids/whitelist.conf";
    blacklist_file = "/etc/hids/blacklist.conf";
    
    /* Répertoire de règles additionnelles (chargées par ordre alphabétique) */
    rules_dir = "/etc/hids/rules.d/";
    
    /*
     * Rechargement automatique des règles
     * Surveille les fichiers de config pour modifications
     */
    auto_reload = true;
    auto_reload_interval_sec = 60;
};
```

### 1.4 Implémentation du parser de configuration

```c
/* config.h */
#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>
#include <stdint.h>

/* Structure de configuration complète */
typedef struct hids_config {
    /* Global */
    int security_level;
    char *mode;
    char *default_action;
    char *run_as_user;
    char *run_as_group;
    char *pid_file;
    
    /* Monitoring */
    char **mount_points;
    size_t mount_points_count;
    char **events;
    size_t events_count;
    char **exclude_paths;
    size_t exclude_paths_count;
    size_t buffer_size;
    int permission_timeout_ms;
    
    /* Logging */
    char *log_destination;
    char *syslog_facility;
    char *syslog_ident;
    char *log_file_path;
    int log_max_size_mb;
    int log_max_files;
    char *log_level;
    char *log_format;
    
    /* Performance */
    int worker_threads;
    int event_queue_size;
    bool unlimited_queue;
    bool unlimited_marks;
    
    /* Rules */
    char *whitelist_file;
    char *blacklist_file;
    char *rules_dir;
    bool auto_reload;
    int auto_reload_interval_sec;
    
} hids_config_t;

/* API */
hids_config_t *config_load(const char *path);
void config_free(hids_config_t *config);
int config_validate(hids_config_t *config);
int config_reload(hids_config_t **config, const char *path);

#endif /* CONFIG_H */
```

```c
/* config.c */
#include "config.h"
#include <libconfig.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

/*
 * Macro helper pour lire une chaîne avec valeur par défaut
 */
#define CONFIG_GET_STRING(cfg, path, dest, default_val) do { \
    const char *_tmp; \
    if (config_lookup_string(cfg, path, &_tmp)) { \
        dest = strdup(_tmp); \
    } else { \
        dest = strdup(default_val); \
    } \
} while(0)

/*
 * Macro helper pour lire un entier avec valeur par défaut
 */
#define CONFIG_GET_INT(cfg, path, dest, default_val) do { \
    if (!config_lookup_int(cfg, path, &dest)) { \
        dest = default_val; \
    } \
} while(0)

/*
 * Macro helper pour lire un booléen avec valeur par défaut
 */
#define CONFIG_GET_BOOL(cfg, path, dest, default_val) do { \
    int _tmp; \
    if (config_lookup_bool(cfg, path, &_tmp)) { \
        dest = _tmp ? true : false; \
    } else { \
        dest = default_val; \
    } \
} while(0)

/*
 * Charge un tableau de chaînes depuis la config
 */
static int load_string_array(config_t *cfg, const char *path, 
                             char ***dest, size_t *count) {
    config_setting_t *setting = config_lookup(cfg, path);
    if (setting == NULL) {
        *dest = NULL;
        *count = 0;
        return 0;
    }
    
    if (config_setting_type(setting) != CONFIG_TYPE_ARRAY) {
        return -1;
    }
    
    int n = config_setting_length(setting);
    *dest = calloc(n + 1, sizeof(char *));  /* +1 pour NULL terminal */
    if (*dest == NULL) return -1;
    
    for (int i = 0; i < n; i++) {
        const char *val = config_setting_get_string_elem(setting, i);
        if (val != NULL) {
            (*dest)[i] = strdup(val);
        }
    }
    
    *count = n;
    return 0;
}

/*
 * config_load - Charge la configuration depuis un fichier
 * 
 * @param path Chemin vers le fichier de configuration
 * @return Configuration chargée ou NULL en cas d'erreur
 * 
 * En cas d'erreur de syntaxe, affiche un message détaillé avec
 * le numéro de ligne et la description de l'erreur.
 */
hids_config_t *config_load(const char *path) {
    config_t cfg;
    config_init(&cfg);
    
    /* Charger et parser le fichier */
    if (!config_read_file(&cfg, path)) {
        syslog(LOG_ERR, "Config error: %s:%d - %s",
               config_error_file(&cfg),
               config_error_line(&cfg),
               config_error_text(&cfg));
        config_destroy(&cfg);
        return NULL;
    }
    
    /* Allouer la structure de configuration */
    hids_config_t *config = calloc(1, sizeof(hids_config_t));
    if (config == NULL) {
        config_destroy(&cfg);
        return NULL;
    }
    
    /* ━━━ Section global ━━━ */
    CONFIG_GET_INT(&cfg, "global.security_level", config->security_level, 5);
    CONFIG_GET_STRING(&cfg, "global.mode", config->mode, "enforce");
    CONFIG_GET_STRING(&cfg, "global.default_action", config->default_action, "allow");
    CONFIG_GET_STRING(&cfg, "global.run_as_user", config->run_as_user, "hids");
    CONFIG_GET_STRING(&cfg, "global.run_as_group", config->run_as_group, "hids");
    CONFIG_GET_STRING(&cfg, "global.pid_file", config->pid_file, "/var/run/hids.pid");
    
    /* ━━━ Section monitoring ━━━ */
    load_string_array(&cfg, "monitoring.mount_points", 
                      &config->mount_points, &config->mount_points_count);
    load_string_array(&cfg, "monitoring.events",
                      &config->events, &config->events_count);
    load_string_array(&cfg, "monitoring.exclude_paths",
                      &config->exclude_paths, &config->exclude_paths_count);
    
    int tmp_int;
    CONFIG_GET_INT(&cfg, "monitoring.buffer_size", tmp_int, 65536);
    config->buffer_size = (size_t)tmp_int;
    CONFIG_GET_INT(&cfg, "monitoring.permission_timeout_ms", 
                   config->permission_timeout_ms, 5000);
    
    /* ━━━ Section logging ━━━ */
    CONFIG_GET_STRING(&cfg, "logging.destination", config->log_destination, "syslog");
    CONFIG_GET_STRING(&cfg, "logging.syslog.facility", config->syslog_facility, "daemon");
    CONFIG_GET_STRING(&cfg, "logging.syslog.ident", config->syslog_ident, "hids");
    CONFIG_GET_STRING(&cfg, "logging.file.path", config->log_file_path, "/var/log/hids.log");
    CONFIG_GET_INT(&cfg, "logging.file.max_size_mb", config->log_max_size_mb, 100);
    CONFIG_GET_INT(&cfg, "logging.file.max_files", config->log_max_files, 10);
    CONFIG_GET_STRING(&cfg, "logging.level", config->log_level, "info");
    
    /* ━━━ Section performance ━━━ */
    CONFIG_GET_INT(&cfg, "performance.worker_threads", config->worker_threads, 4);
    CONFIG_GET_INT(&cfg, "performance.event_queue_size", config->event_queue_size, 10000);
    CONFIG_GET_BOOL(&cfg, "performance.unlimited_queue", config->unlimited_queue, true);
    CONFIG_GET_BOOL(&cfg, "performance.unlimited_marks", config->unlimited_marks, true);
    
    /* ━━━ Section rules ━━━ */
    CONFIG_GET_STRING(&cfg, "rules.whitelist_file", config->whitelist_file, 
                      "/etc/hids/whitelist.conf");
    CONFIG_GET_STRING(&cfg, "rules.blacklist_file", config->blacklist_file,
                      "/etc/hids/blacklist.conf");
    CONFIG_GET_STRING(&cfg, "rules.rules_dir", config->rules_dir, "/etc/hids/rules.d/");
    CONFIG_GET_BOOL(&cfg, "rules.auto_reload", config->auto_reload, true);
    CONFIG_GET_INT(&cfg, "rules.auto_reload_interval_sec", 
                   config->auto_reload_interval_sec, 60);
    
    config_destroy(&cfg);
    return config;
}

/*
 * config_validate - Valide la cohérence de la configuration
 * 
 * Vérifie que les valeurs sont dans les plages acceptables
 * et que les combinaisons de paramètres sont valides.
 */
int config_validate(hids_config_t *config) {
    int errors = 0;
    
    /* Validation security_level */
    if (config->security_level < 0 || config->security_level > 10) {
        syslog(LOG_ERR, "Config: security_level doit être entre 0 et 10");
        errors++;
    }
    
    /* Validation mode */
    if (strcmp(config->mode, "monitor") != 0 && 
        strcmp(config->mode, "enforce") != 0) {
        syslog(LOG_ERR, "Config: mode doit être 'monitor' ou 'enforce'");
        errors++;
    }
    
    /* Validation default_action */
    if (strcmp(config->default_action, "allow") != 0 &&
        strcmp(config->default_action, "deny") != 0) {
        syslog(LOG_ERR, "Config: default_action doit être 'allow' ou 'deny'");
        errors++;
    }
    
    /* Cohérence security_level et default_action */
    if (config->security_level >= 6 && 
        strcmp(config->default_action, "allow") == 0) {
        syslog(LOG_WARNING, "Config: security_level >= 6 avec default_action='allow' "
                            "peut être dangereux. Considérez 'deny'.");
    }
    
    /* Validation buffer_size */
    if (config->buffer_size < 4096) {
        syslog(LOG_ERR, "Config: buffer_size minimum = 4096");
        errors++;
    }
    
    /* Validation worker_threads */
    if (config->worker_threads < 1 || config->worker_threads > 64) {
        syslog(LOG_ERR, "Config: worker_threads doit être entre 1 et 64");
        errors++;
    }
    
    return errors == 0 ? 0 : -1;
}

/*
 * config_free - Libère la mémoire de la configuration
 */
void config_free(hids_config_t *config) {
    if (config == NULL) return;
    
    free(config->mode);
    free(config->default_action);
    free(config->run_as_user);
    free(config->run_as_group);
    free(config->pid_file);
    
    /* Libérer les tableaux de chaînes */
    if (config->mount_points) {
        for (size_t i = 0; i < config->mount_points_count; i++) {
            free(config->mount_points[i]);
        }
        free(config->mount_points);
    }
    
    /* ... idem pour les autres tableaux ... */
    
    free(config->log_destination);
    free(config->syslog_facility);
    free(config->syslog_ident);
    free(config->log_file_path);
    free(config->log_level);
    
    free(config->whitelist_file);
    free(config->blacklist_file);
    free(config->rules_dir);
    
    free(config);
}
```

### 1.5 Hot-reload de la configuration

```c
/*
 * Gestionnaire SIGHUP pour rechargement de configuration
 * 
 * Convention Unix : SIGHUP = "Relire la configuration"
 */

#include <signal.h>
#include <stdatomic.h>

/* Variable atomique pour signaler le besoin de reload */
static atomic_int reload_requested = 0;

/* Gestionnaire de signal - DOIT être async-signal-safe */
static void sighup_handler(int sig) {
    (void)sig;  /* Éviter warning unused */
    atomic_store(&reload_requested, 1);
}

/* Installation du gestionnaire */
void setup_signal_handlers(void) {
    struct sigaction sa = {0};
    sa.sa_handler = sighup_handler;
    sa.sa_flags = SA_RESTART;  /* Redémarrer les appels système interrompus */
    sigemptyset(&sa.sa_mask);
    
    if (sigaction(SIGHUP, &sa, NULL) == -1) {
        syslog(LOG_ERR, "Impossible d'installer le handler SIGHUP: %m");
    }
}

/* Dans la boucle principale */
void main_loop(void) {
    while (running) {
        /* Vérifier si un reload est demandé */
        if (atomic_exchange(&reload_requested, 0)) {
            syslog(LOG_INFO, "SIGHUP reçu, rechargement de la configuration...");
            
            /* Charger la nouvelle configuration */
            hids_config_t *new_config = config_load("/etc/hids/hids.conf");
            if (new_config == NULL) {
                syslog(LOG_ERR, "Échec du rechargement, conservation de l'ancienne config");
                continue;
            }
            
            /* Valider */
            if (config_validate(new_config) != 0) {
                syslog(LOG_ERR, "Nouvelle configuration invalide, conservation de l'ancienne");
                config_free(new_config);
                continue;
            }
            
            /* Appliquer atomiquement */
            hids_config_t *old_config = current_config;
            current_config = new_config;
            
            /* Recharger les listes */
            reload_policy_engine();
            
            /* Libérer l'ancienne config (après un délai pour les threads en cours) */
            sleep(1);
            config_free(old_config);
            
            syslog(LOG_INFO, "Configuration rechargée avec succès");
        }
        
        /* ... traitement normal ... */
    }
}
```

---

## 2. Niveaux de sécurité et modes de réponse

### 2.1 Définition des niveaux de sécurité

Inspiré d'OSSEC (alertes 0-15) et adapté pour fanotify :

```c
/*
 * NIVEAUX DE SÉCURITÉ
 * 
 * Le niveau de sécurité détermine la réponse du HIDS aux différentes
 * situations. Plus le niveau est élevé, plus le système est restrictif.
 */

typedef enum {
    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
    /* NIVEAUX 0-2 : MODE APPRENTISSAGE                                    */
    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
    
    SEC_LEVEL_DISABLED = 0,
    /*
     * Niveau 0 : Désactivé
     * - Logging minimal (erreurs uniquement)
     * - Aucun blocage
     * - Utile pour diagnostic de problèmes
     */
    
    SEC_LEVEL_LEARNING_QUIET = 1,
    /*
     * Niveau 1 : Apprentissage silencieux
     * - Log tous les accès (pour construire une baseline)
     * - Aucun blocage
     * - Aucune alerte
     * - Idéal pour créer automatiquement une whitelist
     */
    
    SEC_LEVEL_LEARNING_VERBOSE = 2,
    /*
     * Niveau 2 : Apprentissage verbeux
     * - Log tous les accès avec détails
     * - Aucun blocage
     * - Alertes informatives (pour review manuel)
     */
    
    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
    /* NIVEAUX 3-5 : MODE STANDARD                                         */
    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
    
    SEC_LEVEL_STANDARD_LOW = 3,
    /*
     * Niveau 3 : Standard bas
     * - Bloque uniquement les accès blacklistés explicites
     * - Log les accès non catégorisés
     * - Alertes sur modifications de fichiers critiques
     */
    
    SEC_LEVEL_STANDARD_MED = 4,
    /*
     * Niveau 4 : Standard moyen (RECOMMANDÉ pour la plupart)
     * - Bloque les accès blacklistés
     * - Alerte sur les accès suspects (non whitelistés sur fichiers sensibles)
     * - Log détaillé
     */
    
    SEC_LEVEL_STANDARD_HIGH = 5,
    /*
     * Niveau 5 : Standard haut
     * - Bloque blacklistés
     * - Bloque les accès en écriture non whitelistés sur fichiers critiques
     * - Alertes sur tout accès inhabituel
     */
    
    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
    /* NIVEAUX 6-8 : MODE RENFORCÉ                                         */
    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
    
    SEC_LEVEL_ENFORCED_LOW = 6,
    /*
     * Niveau 6 : Renforcé bas
     * - Bloque tout accès non whitelisté aux fichiers critiques
     * - Permet les accès non catégorisés aux fichiers non critiques
     */
    
    SEC_LEVEL_ENFORCED_MED = 7,
    /*
     * Niveau 7 : Renforcé moyen
     * - Comme niveau 6
     * - + Bloque les exécutions de binaires non whitelistés
     */
    
    SEC_LEVEL_ENFORCED_HIGH = 8,
    /*
     * Niveau 8 : Renforcé haut
     * - Bloque presque tout ce qui n'est pas whitelisté
     * - Alertes immédiates
     */
    
    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
    /* NIVEAUX 9-10 : MODE PARANOÏAQUE                                     */
    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
    
    SEC_LEVEL_PARANOID = 9,
    /*
     * Niveau 9 : Paranoïaque
     * - DEFAULT DENY : Tout ce qui n'est pas explicitement autorisé est bloqué
     * - Nécessite une whitelist exhaustive
     * - Pour environnements très sensibles (systèmes critiques)
     */
    
    SEC_LEVEL_LOCKDOWN = 10
    /*
     * Niveau 10 : Verrouillage
     * - Comme niveau 9
     * - + Aucune modification de configuration acceptée
     * - + Toute tentative de modification génère une alerte critique
     * - Pour systèmes en production finale où rien ne doit changer
     */
    
} security_level_t;
```

### 2.2 Matrice de décision

```c
/*
 * Matrice de décision selon le niveau de sécurité et le type d'accès
 * 
 * Légende :
 *   A = Allow (autoriser)
 *   D = Deny (bloquer)
 *   L = Log only (autoriser mais logger)
 *   W = Warn (autoriser mais alerte)
 */

typedef enum {
    RESPONSE_ALLOW,
    RESPONSE_DENY,
    RESPONSE_LOG,
    RESPONSE_WARN,
    RESPONSE_ALERT_AND_ALLOW,
    RESPONSE_ALERT_AND_DENY
} response_t;

/*
 * Fonction de décision principale
 */
response_t decide_action(security_level_t level,
                         bool is_blacklisted,
                         bool is_whitelisted,
                         bool is_critical_file,
                         operation_t operation) {
    
    /* Blacklist TOUJOURS prioritaire (sauf niveau 0) */
    if (is_blacklisted && level > SEC_LEVEL_DISABLED) {
        if (level >= SEC_LEVEL_STANDARD_LOW) {
            return RESPONSE_ALERT_AND_DENY;
        }
        return RESPONSE_LOG;  /* Niveaux apprentissage : log seulement */
    }
    
    /* Whitelist explicite */
    if (is_whitelisted) {
        return RESPONSE_ALLOW;
    }
    
    /* Décision selon le niveau pour accès non catégorisé */
    
    /*
     * Table de décision :
     * 
     * Niveau │ Fichier critique │ Fichier normal │ Exécution
     * ───────┼──────────────────┼────────────────┼──────────
     *   0-2  │       L          │       A        │    A
     *   3    │       L          │       A        │    A
     *   4    │       W          │       L        │    L
     *   5    │  W (D si write)  │       L        │    W
     *   6    │       D          │       L        │    W
     *   7    │       D          │       L        │    D
     *   8    │       D          │       W        │    D
     *   9-10 │       D          │       D        │    D
     */
    
    switch (level) {
        case SEC_LEVEL_DISABLED:
            return RESPONSE_ALLOW;
            
        case SEC_LEVEL_LEARNING_QUIET:
        case SEC_LEVEL_LEARNING_VERBOSE:
            return is_critical_file ? RESPONSE_LOG : RESPONSE_ALLOW;
            
        case SEC_LEVEL_STANDARD_LOW:
            return is_critical_file ? RESPONSE_LOG : RESPONSE_ALLOW;
            
        case SEC_LEVEL_STANDARD_MED:
            if (is_critical_file) return RESPONSE_WARN;
            return RESPONSE_LOG;
            
        case SEC_LEVEL_STANDARD_HIGH:
            if (is_critical_file) {
                if (operation == OP_WRITE || operation == OP_DELETE) {
                    return RESPONSE_ALERT_AND_DENY;
                }
                return RESPONSE_WARN;
            }
            return RESPONSE_LOG;
            
        case SEC_LEVEL_ENFORCED_LOW:
            if (is_critical_file) return RESPONSE_ALERT_AND_DENY;
            return RESPONSE_LOG;
            
        case SEC_LEVEL_ENFORCED_MED:
            if (is_critical_file) return RESPONSE_ALERT_AND_DENY;
            if (operation == OP_EXECUTE) return RESPONSE_ALERT_AND_DENY;
            return RESPONSE_LOG;
            
        case SEC_LEVEL_ENFORCED_HIGH:
            if (is_critical_file) return RESPONSE_ALERT_AND_DENY;
            if (operation == OP_EXECUTE) return RESPONSE_ALERT_AND_DENY;
            return RESPONSE_WARN;
            
        case SEC_LEVEL_PARANOID:
        case SEC_LEVEL_LOCKDOWN:
            /* Default deny */
            return RESPONSE_ALERT_AND_DENY;
            
        default:
            return RESPONSE_LOG;
    }
}
```

---

## 3. Sécurisation du code C

### 3.1 Pourquoi c'est critique pour un HIDS

Un HIDS compromis devient lui-même un vecteur d'attaque. Il a accès à :
- Tous les événements fichiers du système
- La capacité de bloquer des accès légitimes (DoS)
- Des privilèges élevés (CAP_SYS_ADMIN au minimum)

### 3.2 Prévention des buffer overflows

```c
/*
 * RÈGLE 1 : Ne JAMAIS utiliser les fonctions non-bornées
 */

/* ❌ INTERDIT */
char buf[256];
strcpy(buf, user_input);           /* Overflow si input > 255 */
sprintf(buf, "Value: %s", input);  /* Idem */
gets(buf);                         /* JAMAIS - supprimé en C11 */

/* ✅ CORRECT */
char buf[256];

/* strncpy + terminaison explicite */
strncpy(buf, user_input, sizeof(buf) - 1);
buf[sizeof(buf) - 1] = '\0';

/* snprintf + vérification */
int written = snprintf(buf, sizeof(buf), "Value: %s", input);
if (written >= (int)sizeof(buf)) {
    /* Troncation ! Logger ou gérer l'erreur */
    syslog(LOG_WARNING, "Output truncated");
}

/* fgets pour lecture */
if (fgets(buf, sizeof(buf), stdin) == NULL) {
    /* Erreur ou EOF */
}

/*
 * RÈGLE 2 : Utiliser des fonctions sécurisées
 */

/* strlcpy/strlcat (BSD, disponible via libbsd sur Linux) */
#include <bsd/string.h>
size_t result = strlcpy(dest, src, sizeof(dest));
if (result >= sizeof(dest)) {
    /* Troncation */
}

/*
 * RÈGLE 3 : Valider TOUTES les entrées
 */

int validate_path(const char *path) {
    /* Vérifier la longueur */
    size_t len = strlen(path);
    if (len == 0 || len >= PATH_MAX) {
        return -1;
    }
    
    /* Vérifier les caractères nuls intégrés (path traversal) */
    if (memchr(path, '\0', len) != path + len) {
        return -1;
    }
    
    /* Vérifier les traversées de répertoire */
    if (strstr(path, "/../") != NULL || 
        strncmp(path, "../", 3) == 0) {
        return -1;
    }
    
    /* Doit être un chemin absolu */
    if (path[0] != '/') {
        return -1;
    }
    
    return 0;
}
```

### 3.3 Gestion mémoire sécurisée

```c
/*
 * PROBLÈME : memset() peut être optimisé par le compilateur
 * 
 * Le compilateur peut supprimer un memset() s'il détecte que la
 * mémoire n'est plus utilisée après. C'est un problème pour effacer
 * des données sensibles (clés, mots de passe).
 */

/* ❌ DANGEREUX */
void process_password(const char *password) {
    char local_copy[256];
    strncpy(local_copy, password, sizeof(local_copy));
    
    /* ... traitement ... */
    
    memset(local_copy, 0, sizeof(local_copy));
    /* ⚠️ Le compilateur peut supprimer ce memset car local_copy
     * n'est plus utilisé après ! */
}

/* ✅ SOLUTION 1 : explicit_bzero (glibc 2.25+) */
#include <string.h>

void process_password_safe1(const char *password) {
    char local_copy[256];
    strncpy(local_copy, password, sizeof(local_copy));
    
    /* ... traitement ... */
    
    explicit_bzero(local_copy, sizeof(local_copy));
    /* explicit_bzero est garanti de ne PAS être optimisé */
}

/* ✅ SOLUTION 2 : Pointeur volatile (portable) */
static void * (* const volatile secure_memset)(void *, int, size_t) = memset;

void secure_zero(void *ptr, size_t size) {
    /* Le volatile empêche l'optimisation */
    (secure_memset)(ptr, 0, size);
}

/* ✅ SOLUTION 3 : Barrière mémoire + volatile */
void secure_zero_v2(void *ptr, size_t size) {
    volatile unsigned char *p = ptr;
    while (size--) {
        *p++ = 0;
    }
    /* Barrière pour empêcher réordonnancement */
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
}

/*
 * Wrapper d'allocation sécurisée
 */
void *secure_malloc(size_t size) {
    void *ptr = malloc(size);
    if (ptr != NULL) {
        /* Initialiser à zéro pour éviter les fuites d'info */
        memset(ptr, 0, size);
    }
    return ptr;
}

void secure_free(void *ptr, size_t size) {
    if (ptr != NULL) {
        /* Effacer avant de libérer */
        secure_zero(ptr, size);
        free(ptr);
    }
}

/*
 * Pour les structures avec taille dynamique
 */
typedef struct {
    size_t allocated_size;
    char data[];
} secure_buffer_t;

secure_buffer_t *secure_buffer_alloc(size_t size) {
    secure_buffer_t *buf = malloc(sizeof(secure_buffer_t) + size);
    if (buf) {
        buf->allocated_size = size;
        memset(buf->data, 0, size);
    }
    return buf;
}

void secure_buffer_free(secure_buffer_t *buf) {
    if (buf) {
        secure_zero(buf->data, buf->allocated_size);
        buf->allocated_size = 0;
        free(buf);
    }
}
```

### 3.4 Prévention des integer overflows

```c
/*
 * Les integer overflows peuvent causer des buffer overflows
 * Exemple : size = n * sizeof(item) peut overflow si n est très grand
 */

#include <stdint.h>

/* ❌ DANGEREUX */
void *allocate_array_bad(size_t count, size_t elem_size) {
    size_t total = count * elem_size;  /* Peut overflow ! */
    return malloc(total);
}

/* ✅ SOLUTION : Vérifier l'overflow */

/* Méthode 1 : Vérification explicite */
void *allocate_array_safe(size_t count, size_t elem_size) {
    /* Vérifier si la multiplication overflow */
    if (elem_size != 0 && count > SIZE_MAX / elem_size) {
        errno = ENOMEM;
        return NULL;
    }
    
    size_t total = count * elem_size;
    return malloc(total);
}

/* Méthode 2 : Utiliser calloc (fait la vérification pour vous) */
void *allocate_array_safe2(size_t count, size_t elem_size) {
    /* calloc vérifie l'overflow ET initialise à zéro */
    return calloc(count, elem_size);
}

/* Méthode 3 : Builtins GCC (GCC 5+) */
void *allocate_array_safe3(size_t count, size_t elem_size) {
    size_t total;
    
    /* __builtin_mul_overflow retourne true si overflow */
    if (__builtin_mul_overflow(count, elem_size, &total)) {
        errno = ENOMEM;
        return NULL;
    }
    
    return malloc(total);
}

/*
 * Pour les additions aussi
 */
int safe_add(size_t a, size_t b, size_t *result) {
    if (a > SIZE_MAX - b) {
        return -1;  /* Overflow */
    }
    *result = a + b;
    return 0;
}
```

---

## 4. Abandon de privilèges

### 4.1 Pourquoi et quand abandonner les privilèges

```
fanotify_init() avec FAN_CLASS_CONTENT requiert CAP_SYS_ADMIN
                    │
                    ▼
    ┌───────────────────────────────────────┐
    │       Démarrage en root               │
    │  • fanotify_init()                    │
    │  • fanotify_mark() sur les mounts     │
    │  • Ouverture des fichiers de config   │
    │  • Création du fichier PID            │
    │  • Binding des sockets d'alerte       │
    └───────────────────────────────────────┘
                    │
                    ▼
    ┌───────────────────────────────────────┐
    │     DROP PRIVILEGES                   │
    │  • Garder uniquement les fd ouverts   │
    │  • Changer vers utilisateur non-root  │
    └───────────────────────────────────────┘
                    │
                    ▼
    ┌───────────────────────────────────────┐
    │    Exécution normale non-root         │
    │  • Lecture events fanotify            │
    │  • Traitement                         │
    │  • Réponses                           │
    │  • Logging                            │
    └───────────────────────────────────────┘
```

### 4.2 Implémentation correcte du drop de privilèges

```c
#define _GNU_SOURCE
#include <sys/types.h>
#include <unistd.h>
#include <grp.h>
#include <pwd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>

/*
 * ORDRE CRITIQUE DES OPÉRATIONS :
 * 
 * 1. setgroups()  - Supprimer les groupes supplémentaires
 * 2. setgid()     - Changer le GID
 * 3. setuid()     - Changer l'UID (EN DERNIER !)
 * 
 * Pourquoi cet ordre ?
 * - setgroups() nécessite CAP_SETGID (ou root)
 * - setgid() nécessite CAP_SETGID (ou root)
 * - Une fois setuid() appelé avec un UID non-root, 
 *   on ne peut plus appeler les autres !
 */

int drop_privileges(const char *username, const char *groupname) {
    
    /* Vérifier qu'on est root */
    if (geteuid() != 0) {
        syslog(LOG_ERR, "drop_privileges: pas root, impossible de drop");
        return -1;
    }
    
    /* Résoudre l'utilisateur */
    struct passwd *pw = getpwnam(username);
    if (pw == NULL) {
        syslog(LOG_ERR, "drop_privileges: utilisateur '%s' inconnu", username);
        return -1;
    }
    
    uid_t target_uid = pw->pw_uid;
    gid_t target_gid = pw->pw_gid;
    
    /* Si un groupe spécifique est demandé */
    if (groupname != NULL) {
        struct group *gr = getgrnam(groupname);
        if (gr == NULL) {
            syslog(LOG_ERR, "drop_privileges: groupe '%s' inconnu", groupname);
            return -1;
        }
        target_gid = gr->gr_gid;
    }
    
    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
    /* ÉTAPE 1 : Supprimer les groupes supplémentaires                     */
    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
    
    /*
     * Pourquoi c'est important ?
     * 
     * Le processus root peut être membre de groupes supplémentaires
     * (wheel, adm, sudo, etc.). Ces groupes peuvent donner des accès
     * que l'utilisateur cible ne devrait pas avoir.
     */
    if (setgroups(0, NULL) == -1) {
        syslog(LOG_ERR, "drop_privileges: setgroups() failed: %s", 
               strerror(errno));
        return -1;
    }
    
    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
    /* ÉTAPE 2 : Changer le GID                                            */
    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
    
    if (setgid(target_gid) == -1) {
        syslog(LOG_ERR, "drop_privileges: setgid(%d) failed: %s",
               target_gid, strerror(errno));
        return -1;
    }
    
    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
    /* ÉTAPE 3 : Changer l'UID (POINT DE NON-RETOUR)                       */
    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
    
    if (setuid(target_uid) == -1) {
        syslog(LOG_ERR, "drop_privileges: setuid(%d) failed: %s",
               target_uid, strerror(errno));
        return -1;
    }
    
    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
    /* ÉTAPE 4 : VÉRIFICATION CRITIQUE                                     */
    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
    
    /*
     * TOUJOURS vérifier qu'on ne peut PAS regagner root !
     * 
     * Sur certains systèmes, setuid() peut ne pas effacer le "saved uid"
     * ce qui permettrait de revenir à root.
     */
    
    /* Tenter de regagner root */
    if (setuid(0) != -1) {
        /* CATASTROPHE : On peut redevenir root ! */
        syslog(LOG_CRIT, "SECURITY: Able to regain root after drop!");
        _exit(EXIT_FAILURE);  /* Terminer immédiatement */
    }
    
    if (seteuid(0) != -1) {
        syslog(LOG_CRIT, "SECURITY: Able to regain euid 0 after drop!");
        _exit(EXIT_FAILURE);
    }
    
    /* Vérifier les IDs finaux */
    if (getuid() != target_uid || geteuid() != target_uid) {
        syslog(LOG_CRIT, "SECURITY: UID mismatch after drop!");
        _exit(EXIT_FAILURE);
    }
    
    if (getgid() != target_gid || getegid() != target_gid) {
        syslog(LOG_CRIT, "SECURITY: GID mismatch after drop!");
        _exit(EXIT_FAILURE);
    }
    
    syslog(LOG_INFO, "Privileges dropped to %s:%s (uid=%d, gid=%d)",
           username, groupname ? groupname : pw->pw_name,
           target_uid, target_gid);
    
    return 0;
}
```

### 4.3 Garder des capabilities spécifiques (optionnel)

```c
/*
 * Si vous devez garder certaines capabilities après le drop
 * (par exemple CAP_AUDIT_WRITE pour les logs audit)
 */

#include <sys/capability.h>
#include <sys/prctl.h>

int drop_privileges_keep_caps(const char *username, const char *groupname,
                               cap_value_t *keep_caps, int num_caps) {
    
    /* Permettre de garder des capabilities après setuid */
    if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == -1) {
        syslog(LOG_ERR, "prctl(PR_SET_KEEPCAPS) failed: %s", strerror(errno));
        return -1;
    }
    
    /* Drop normal */
    if (drop_privileges(username, groupname) != 0) {
        return -1;
    }
    
    /* Maintenant, restaurer les capabilities désirées */
    cap_t caps = cap_get_proc();
    if (caps == NULL) {
        syslog(LOG_ERR, "cap_get_proc() failed: %s", strerror(errno));
        return -1;
    }
    
    /* Effacer toutes les capabilities */
    if (cap_clear(caps) == -1) {
        cap_free(caps);
        return -1;
    }
    
    /* Ajouter uniquement celles qu'on veut garder */
    if (num_caps > 0 && keep_caps != NULL) {
        if (cap_set_flag(caps, CAP_PERMITTED, num_caps, keep_caps, CAP_SET) == -1 ||
            cap_set_flag(caps, CAP_EFFECTIVE, num_caps, keep_caps, CAP_SET) == -1) {
            cap_free(caps);
            return -1;
        }
    }
    
    /* Appliquer */
    if (cap_set_proc(caps) == -1) {
        syslog(LOG_ERR, "cap_set_proc() failed: %s", strerror(errno));
        cap_free(caps);
        return -1;
    }
    
    cap_free(caps);
    
    /* Désactiver KEEPCAPS pour empêcher d'ajouter des caps plus tard */
    prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0);
    
    return 0;
}

/* Exemple d'utilisation */
void init_with_audit_cap(void) {
    cap_value_t keep[] = { CAP_AUDIT_WRITE };
    
    if (drop_privileges_keep_caps("hids", "hids", keep, 1) != 0) {
        exit(EXIT_FAILURE);
    }
    
    /* Maintenant on peut écrire des logs audit mais rien d'autre */
}
```

---

## 5. Sandboxing avec seccomp

### 5.1 Qu'est-ce que seccomp ?

**seccomp** (Secure Computing Mode) permet de **filtrer les appels système** qu'un processus peut effectuer. C'est une couche de défense supplémentaire : même si un attaquant exploite une vulnérabilité dans votre HIDS, il sera limité aux syscalls autorisés.

```
Sans seccomp :
  Attaquant exploite buffer overflow
        │
        ▼
  Exécute shellcode
        │
        ▼
  Peut appeler N'IMPORTE QUEL syscall
  (execve pour shell, socket pour C&C, etc.)

Avec seccomp :
  Attaquant exploite buffer overflow
        │
        ▼
  Exécute shellcode
        │
        ▼
  Tente d'appeler execve()
        │
        ▼
  SIGKILL (syscall non autorisé)
```

### 5.2 Implémentation seccomp-BPF

```c
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <stddef.h>

/*
 * Liste des syscalls nécessaires pour le HIDS
 * Cette liste doit être la plus restrictive possible
 */
static const int allowed_syscalls[] = {
    /* Lecture/écriture de base */
    __NR_read,
    __NR_write,
    __NR_close,
    
    /* fanotify */
    /* Note: fanotify_init n'est pas nécessaire après l'init */
    __NR_fanotify_mark,  /* Pour ajouter/retirer des marks dynamiquement */
    
    /* Fichiers (en lecture seule après init) */
    __NR_fstat,
    __NR_lseek,
    __NR_readlink,
    
    /* Réseau (pour alertes) - restreindre davantage si possible */
    __NR_sendto,
    __NR_recvfrom,
    
    /* Mémoire */
    __NR_mmap,
    __NR_munmap,
    __NR_mprotect,
    __NR_brk,
    
    /* Signaux */
    __NR_rt_sigaction,
    __NR_rt_sigprocmask,
    __NR_rt_sigreturn,
    
    /* Temps */
    __NR_clock_gettime,
    __NR_nanosleep,
    
    /* Polling */
    __NR_poll,
    __NR_epoll_wait,
    __NR_epoll_ctl,
    __NR_epoll_create1,
    
    /* Threading */
    __NR_futex,
    __NR_set_robust_list,
    
    /* Divers */
    __NR_exit,
    __NR_exit_group,
    __NR_getpid,
    __NR_gettid,
    __NR_getrandom,
    
    /* prctl pour seccomp lui-même */
    __NR_prctl,
};

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/*
 * Construire et installer le filtre seccomp
 */
int install_seccomp_filter(void) {
    
    /* Empêcher l'acquisition de nouveaux privilèges */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        syslog(LOG_ERR, "prctl(NO_NEW_PRIVS) failed: %s", strerror(errno));
        return -1;
    }
    
    /*
     * Construction du filtre BPF
     * 
     * Le filtre est une série d'instructions BPF qui :
     * 1. Vérifie l'architecture (protection contre confusion 32/64 bit)
     * 2. Charge le numéro de syscall
     * 3. Compare avec la whitelist
     * 4. Autorise ou kill le processus
     */
    
    /* Taille estimée du filtre */
    size_t num_syscalls = ARRAY_SIZE(allowed_syscalls);
    size_t filter_size = 4 + num_syscalls + 2;  /* header + syscalls + footer */
    
    struct sock_filter *filter = calloc(filter_size, sizeof(struct sock_filter));
    if (filter == NULL) {
        return -1;
    }
    
    size_t idx = 0;
    
    /* Vérifier l'architecture */
    filter[idx++] = (struct sock_filter)BPF_STMT(
        BPF_LD | BPF_W | BPF_ABS,
        offsetof(struct seccomp_data, arch)
    );
    
#if defined(__x86_64__)
    filter[idx++] = (struct sock_filter)BPF_JUMP(
        BPF_JMP | BPF_JEQ | BPF_K,
        AUDIT_ARCH_X86_64,
        1, 0  /* Si match, continuer; sinon, next instruction */
    );
#elif defined(__i386__)
    filter[idx++] = (struct sock_filter)BPF_JUMP(
        BPF_JMP | BPF_JEQ | BPF_K,
        AUDIT_ARCH_I386,
        1, 0
    );
#else
    #error "Architecture non supportée"
#endif
    
    /* Si architecture incorrecte, KILL */
    filter[idx++] = (struct sock_filter)BPF_STMT(
        BPF_RET | BPF_K,
        SECCOMP_RET_KILL
    );
    
    /* Charger le numéro de syscall */
    filter[idx++] = (struct sock_filter)BPF_STMT(
        BPF_LD | BPF_W | BPF_ABS,
        offsetof(struct seccomp_data, nr)
    );
    
    /* Pour chaque syscall autorisé, ajouter un jump conditionnel */
    for (size_t i = 0; i < num_syscalls; i++) {
        filter[idx++] = (struct sock_filter)BPF_JUMP(
            BPF_JMP | BPF_JEQ | BPF_K,
            allowed_syscalls[i],
            num_syscalls - i,  /* Jump to ALLOW */
            0                   /* Continue checking */
        );
    }
    
    /* Si aucun match, KILL */
    filter[idx++] = (struct sock_filter)BPF_STMT(
        BPF_RET | BPF_K,
        SECCOMP_RET_KILL
    );
    
    /* Si match, ALLOW */
    filter[idx++] = (struct sock_filter)BPF_STMT(
        BPF_RET | BPF_K,
        SECCOMP_RET_ALLOW
    );
    
    /* Installer le filtre */
    struct sock_fprog prog = {
        .len = idx,
        .filter = filter,
    };
    
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
        syslog(LOG_ERR, "prctl(SECCOMP_MODE_FILTER) failed: %s", strerror(errno));
        free(filter);
        return -1;
    }
    
    free(filter);
    syslog(LOG_INFO, "Seccomp filter installed (%zu syscalls allowed)", num_syscalls);
    return 0;
}
```

### 5.3 Alternative : libseccomp (plus simple)

```c
/*
 * libseccomp offre une API de plus haut niveau
 * Installation : apt install libseccomp-dev
 */

#include <seccomp.h>

int install_seccomp_libseccomp(void) {
    scmp_filter_ctx ctx;
    
    /* Créer un contexte avec action par défaut = KILL */
    ctx = seccomp_init(SCMP_ACT_KILL);
    if (ctx == NULL) {
        return -1;
    }
    
    /* Ajouter les syscalls autorisés */
    int rc = 0;
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(poll), 0);
    rc |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    /* ... etc ... */
    
    if (rc != 0) {
        seccomp_release(ctx);
        return -1;
    }
    
    /* Charger le filtre */
    rc = seccomp_load(ctx);
    if (rc != 0) {
        seccomp_release(ctx);
        return -1;
    }
    
    seccomp_release(ctx);
    return 0;
}
```

---

## Résumé des points clés de cette partie

1. **Configuration** :
   - Utilisez libconfig pour un format lisible et maintenable
   - Supportez le hot-reload via SIGHUP
   - Validez toujours la configuration après chargement

2. **Niveaux de sécurité** :
   - Implémentez plusieurs niveaux (0-10) pour s'adapter aux besoins
   - Mode apprentissage pour créer les règles initiales
   - Mode paranoïaque pour les environnements critiques

3. **Sécurité du code** :
   - Utilisez snprintf, pas sprintf
   - Effacez les données sensibles avec explicit_bzero
   - Vérifiez les overflows arithmétiques

4. **Drop de privilèges** :
   - Ordre : setgroups → setgid → setuid
   - TOUJOURS vérifier qu'on ne peut pas regagner root
   - Faire le drop après l'initialisation fanotify

5. **Seccomp** :
   - Filtrer les syscalls pour limiter la surface d'attaque
   - Utiliser libseccomp pour simplifier l'implémentation

---

## Références

- libconfig : https://hyperrealm.github.io/libconfig/
- CERT C Secure Coding : https://wiki.sei.cmu.edu/confluence/display/c/
- explicit_bzero : https://www.gnu.org/software/libc/manual/html_node/Erasing-Sensitive-Data.html
- Privilege dropping : https://dwheeler.com/secure-programs/Secure-Programs-HOWTO/minimize-privileges.html
- seccomp : https://docs.kernel.org/userspace-api/seccomp_filter.html
- libseccomp : https://github.com/seccomp/libseccomp
