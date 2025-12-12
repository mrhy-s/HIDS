# Guide HIDS en C avec fanotify — Partie 2 : Architecture et Système de Listes

## Table des matières
1. [Architecture globale du HIDS](#1-architecture-globale-du-hids)
2. [Structures de données pour les listes](#2-structures-de-données-pour-les-listes)
3. [Implémentation des listes avec hash tables](#3-implémentation-des-listes-avec-hash-tables)
4. [Implémentation avec Trie pour correspondance par préfixe](#4-implémentation-avec-trie-pour-correspondance-par-préfixe)
5. [Système hybride haute performance](#5-système-hybride-haute-performance)

---

## 1. Architecture globale du HIDS

### 1.1 Vue d'ensemble des composants

Un HIDS production-ready se compose de plusieurs modules interconnectés :

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ARCHITECTURE HIDS                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                     CONFIGURATION MANAGER                            │   │
│   │  • Charge les fichiers de config au démarrage                       │   │
│   │  • Gère le hot-reload via SIGHUP                                    │   │
│   │  • Valide la syntaxe et la cohérence                                │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                      │                                       │
│                                      ▼                                       │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                      POLICY ENGINE                                   │   │
│   │  ┌─────────────┐  ┌─────────────┐  ┌────────────────────────────┐  │   │
│   │  │  Whitelist  │  │  Blacklist  │  │  Security Levels           │  │   │
│   │  │  (Hash +    │  │  (Hash +    │  │  • Level 0-2: Log only     │  │   │
│   │  │   Trie)     │  │   Trie)     │  │  • Level 3-5: Alert        │  │   │
│   │  │             │  │             │  │  • Level 6+:  Block        │  │   │
│   │  └─────────────┘  └─────────────┘  └────────────────────────────┘  │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                      │                                       │
│                                      ▼                                       │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                      EVENT PROCESSOR                                 │   │
│   │                                                                      │   │
│   │   ┌──────────────┐     ┌──────────────┐     ┌──────────────────┐   │   │
│   │   │   Reader     │────▶│  Ring Buffer │────▶│  Worker Threads  │   │   │
│   │   │   Thread     │     │              │     │  (N threads)     │   │   │
│   │   │              │     │              │     │                  │   │   │
│   │   │  epoll +     │     │  Lock-free   │     │  • Évaluation    │   │   │
│   │   │  fanotify fd │     │  SPMC queue  │     │  • Décision      │   │   │
│   │   └──────────────┘     └──────────────┘     │  • Réponse       │   │   │
│   │                                             └──────────────────┘   │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                      │                                       │
│                                      ▼                                       │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                      LOGGING & ALERTING                              │   │
│   │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────────┐  │   │
│   │  │   Syslog    │  │   File Log  │  │   External (SIEM, email)   │  │   │
│   │  └─────────────┘  └─────────────┘  └─────────────────────────────┘  │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Flux de décision détaillé

Pour chaque événement reçu, voici le flux de décision recommandé :

```c
/*
 * ALGORITHME DE DÉCISION
 * 
 * Entrée : événement fanotify (fichier, PID, type d'accès)
 * Sortie : FAN_ALLOW ou FAN_DENY
 */

enum decision_t {
    DECISION_ALLOW,
    DECISION_DENY,
    DECISION_LOG_ONLY,
    DECISION_ALERT
};

decision_t evaluate_event(event_t *event) {
    
    /* ÉTAPE 1 : Auto-exclusion (éviter deadlock) */
    if (event->pid == our_pid) {
        return DECISION_ALLOW;
    }
    
    /* ÉTAPE 2 : Vérifier la blacklist (priorité maximale) */
    /*
     * La blacklist est vérifiée EN PREMIER car :
     * - Une entrée blacklist est une interdiction explicite
     * - Elle prime sur tout le reste
     * - Exemple : /etc/shadow ne devrait JAMAIS être accessible
     *   par un processus non-root, même s'il est whitelisté
     */
    blacklist_entry_t *bl_entry = blacklist_lookup(event->path);
    if (bl_entry != NULL) {
        /* Vérifier si l'exception s'applique */
        if (!blacklist_exception_applies(bl_entry, event)) {
            log_blocked_access(event, bl_entry->reason);
            return DECISION_DENY;
        }
    }
    
    /* ÉTAPE 3 : Vérifier la whitelist */
    /*
     * La whitelist définit ce qui est "normal" et attendu.
     * Si un accès n'est pas dans la whitelist, il est suspect.
     */
    whitelist_entry_t *wl_entry = whitelist_lookup(event->path);
    if (wl_entry != NULL) {
        /* L'accès est explicitement autorisé */
        
        /* Mais vérifier les conditions supplémentaires */
        if (wl_entry->allowed_pids != NULL) {
            if (!pid_in_list(event->pid, wl_entry->allowed_pids)) {
                /* PID non autorisé pour ce fichier */
                return evaluate_security_level(event, LEVEL_SUSPICIOUS);
            }
        }
        
        return DECISION_ALLOW;
    }
    
    /* ÉTAPE 4 : Accès ni blacklisté ni whitelisté */
    /*
     * C'est la zone grise. Le comportement dépend du niveau de sécurité.
     */
    return evaluate_security_level(event, LEVEL_UNKNOWN);
}

decision_t evaluate_security_level(event_t *event, threat_level_t threat) {
    /*
     * Niveaux de sécurité inspirés d'OSSEC :
     * 
     * SECURITY_LEVEL_PERMISSIVE (0-2) :
     *   - Log tout, ne bloque rien
     *   - Utile en phase d'apprentissage
     * 
     * SECURITY_LEVEL_STANDARD (3-5) :
     *   - Log les accès inconnus
     *   - Alerte sur les accès suspects
     *   - Ne bloque que les blacklistés explicites
     * 
     * SECURITY_LEVEL_PARANOID (6+) :
     *   - Bloque tout ce qui n'est pas explicitement whitelisté
     *   - "Default deny"
     */
    
    switch (current_security_level) {
        case SECURITY_LEVEL_PERMISSIVE:
            if (threat >= LEVEL_SUSPICIOUS) {
                log_suspicious_access(event);
            }
            return DECISION_ALLOW;
            
        case SECURITY_LEVEL_STANDARD:
            if (threat >= LEVEL_SUSPICIOUS) {
                alert_suspicious_access(event);
            }
            return DECISION_ALLOW;
            
        case SECURITY_LEVEL_PARANOID:
            if (threat >= LEVEL_UNKNOWN) {
                alert_unknown_access(event);
                return DECISION_DENY;
            }
            return DECISION_ALLOW;
            
        default:
            return DECISION_ALLOW;
    }
}
```

### 1.3 Fichiers critiques à surveiller

Basé sur les meilleures pratiques OSSEC, Samhain, et les recommandations CIS Benchmarks :

```c
/* 
 * CATÉGORIE 1 : Authentification et contrôle d'accès
 * Criticité : MAXIMALE
 * Ces fichiers sont les cibles principales des attaquants
 */
static const char *auth_files[] = {
    "/etc/passwd",          /* Base de données utilisateurs */
    "/etc/shadow",          /* Mots de passe hashés */
    "/etc/group",           /* Groupes */
    "/etc/gshadow",         /* Mots de passe groupes */
    "/etc/sudoers",         /* Configuration sudo */
    "/etc/sudoers.d/",      /* Configurations sudo additionnelles */
    "/etc/pam.d/",          /* Configuration PAM */
    "/etc/security/",       /* Politiques de sécurité */
    "/etc/login.defs",      /* Paramètres login */
    NULL
};

/*
 * CATÉGORIE 2 : SSH
 * Criticité : ÉLEVÉE  
 * Vecteur d'accès distant très ciblé
 */
static const char *ssh_files[] = {
    "/etc/ssh/sshd_config",              /* Config serveur SSH */
    "/etc/ssh/ssh_config",               /* Config client SSH */
    "/root/.ssh/",                       /* Clés root */
    "/home/*/.ssh/authorized_keys",      /* Clés autorisées (pattern) */
    NULL
};

/*
 * CATÉGORIE 3 : Persistance (mécanismes utilisés par les attaquants)
 * Criticité : ÉLEVÉE
 */
static const char *persistence_files[] = {
    /* Cron */
    "/etc/crontab",
    "/etc/cron.d/",
    "/etc/cron.daily/",
    "/etc/cron.hourly/",
    "/etc/cron.weekly/",
    "/etc/cron.monthly/",
    "/var/spool/cron/",
    
    /* Systemd */
    "/etc/systemd/system/",
    "/lib/systemd/system/",
    "/usr/lib/systemd/system/",
    
    /* Init scripts */
    "/etc/init.d/",
    "/etc/rc.local",
    "/etc/rc.d/",
    
    /* Shell profiles (exécutés à chaque login) */
    "/etc/profile",
    "/etc/profile.d/",
    "/etc/bash.bashrc",
    "/root/.bashrc",
    "/root/.bash_profile",
    "/root/.profile",
    
    NULL
};

/*
 * CATÉGORIE 4 : Binaires système
 * Criticité : CRITIQUE
 * Modification = compromission complète
 */
static const char *system_binaries[] = {
    "/bin/",
    "/sbin/",
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/local/bin/",
    "/usr/local/sbin/",
    NULL
};

/*
 * CATÉGORIE 5 : Logs système
 * Criticité : MOYENNE à ÉLEVÉE
 * Les attaquants tentent souvent de les effacer ou modifier
 */
static const char *log_files[] = {
    "/var/log/auth.log",           /* Debian/Ubuntu : authentification */
    "/var/log/secure",             /* RHEL/CentOS : authentification */
    "/var/log/syslog",             /* Logs système généraux */
    "/var/log/messages",           /* Logs système (RHEL) */
    "/var/log/audit/",             /* Logs audit */
    "/var/log/wtmp",               /* Historique connexions (binaire) */
    "/var/log/btmp",               /* Tentatives échouées (binaire) */
    "/var/log/lastlog",            /* Dernières connexions */
    NULL
};

/*
 * CATÉGORIE 6 : Configuration réseau
 * Criticité : ÉLEVÉE
 */
static const char *network_files[] = {
    "/etc/hosts",                   /* Résolution DNS locale */
    "/etc/hosts.allow",            /* TCP wrappers allow */
    "/etc/hosts.deny",             /* TCP wrappers deny */
    "/etc/resolv.conf",            /* Serveurs DNS */
    "/etc/network/interfaces",      /* Config réseau Debian */
    "/etc/sysconfig/network-scripts/", /* Config réseau RHEL */
    "/etc/iptables/",              /* Règles firewall */
    "/etc/nftables.conf",          /* NFTables config */
    NULL
};
```

---

## 2. Structures de données pour les listes

### 2.1 Comprendre les besoins de performance

Pour un HIDS en production, chaque événement doit être traité **rapidement**. Voici les contraintes :

```
Événements fanotify possibles : 1000-10000+/seconde sur un serveur actif

Si le traitement d'un événement prend :
  - 1 ms   → Peut traiter ~1000 événements/seconde (limite basse)
  - 100 µs → Peut traiter ~10000 événements/seconde (acceptable)
  - 10 µs  → Peut traiter ~100000 événements/seconde (confortable)

Le lookup dans les listes doit être << 10 µs pour ne pas être le goulot
```

### 2.2 Comparaison des structures de données

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ STRUCTURE     │ LOOKUP    │ INSERT    │ MÉMOIRE  │ CAS D'UTILISATION        │
├─────────────────────────────────────────────────────────────────────────────┤
│ Liste chaînée │ O(n)      │ O(1)      │ Faible   │ Petites listes (<100)    │
│               │           │           │          │ Rarement utilisée        │
├─────────────────────────────────────────────────────────────────────────────┤
│ Tableau trié  │ O(log n)  │ O(n)      │ Faible   │ Listes statiques         │
│ + recherche   │           │           │          │ (pas de modif runtime)   │
│ binaire       │           │           │          │                          │
├─────────────────────────────────────────────────────────────────────────────┤
│ Hash table    │ O(1)*     │ O(1)*     │ Moyen    │ Chemins exacts           │
│               │ amortized │ amortized │          │ "/etc/passwd"            │
├─────────────────────────────────────────────────────────────────────────────┤
│ Trie          │ O(m)      │ O(m)      │ Élevé    │ Correspondance préfixe   │
│ (m=longueur   │           │           │          │ "/etc/*" match /etc/foo  │
│  du chemin)   │           │           │          │                          │
├─────────────────────────────────────────────────────────────────────────────┤
│ Radix tree    │ O(m)      │ O(m)      │ Moyen    │ Préfixes avec compression│
│ (Patricia)    │           │           │          │ Plus compact que Trie    │
├─────────────────────────────────────────────────────────────────────────────┤
│ Bloom filter  │ O(k)      │ O(k)      │ Très     │ Pré-filtrage rapide      │
│ + backup      │ k=hash    │           │ faible   │ "Probablement pas dans   │
│               │ functions │           │          │  la liste" = certain     │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.3 Stratégie recommandée : Approche hybride

Pour un HIDS, on combine plusieurs structures :

```c
/*
 * ARCHITECTURE DES LISTES
 * 
 * Objectif : Répondre à deux types de règles
 * 
 * TYPE 1 : Règles exactes
 *   "/etc/passwd" → Surveiller CE fichier précis
 *   → Hash table (lookup O(1))
 * 
 * TYPE 2 : Règles par préfixe
 *   "/etc/" → Surveiller TOUT ce qui commence par /etc/
 *   "/var/log/" → Surveiller TOUS les logs
 *   → Trie (lookup O(longueur du chemin))
 * 
 * FLUX DE VÉRIFICATION :
 * 
 *   Chemin reçu: "/etc/passwd"
 *        │
 *        ▼
 *   ┌─────────────────────────────────────┐
 *   │ 1. Chercher dans hash table exacte  │ O(1)
 *   │    Clé: "/etc/passwd"               │
 *   └─────────────────────────────────────┘
 *        │
 *        │ Pas trouvé
 *        ▼
 *   ┌─────────────────────────────────────┐
 *   │ 2. Chercher préfixe le plus long    │ O(m)
 *   │    dans le Trie                     │
 *   │    Trouve: "/etc/" (wildcard)       │
 *   └─────────────────────────────────────┘
 *        │
 *        ▼
 *   Appliquer la règle trouvée
 */
```

---

## 3. Implémentation des listes avec hash tables

### 3.1 Introduction à uthash

**uthash** est une bibliothèque header-only (un seul fichier .h) pour implémenter des hash tables en C. Elle est idéale pour notre cas car :

- Aucune dépendance externe
- Intrusive (la structure de données est dans votre struct)
- Bien testée et utilisée dans de nombreux projets

**Source** : https://troydhanson.github.io/uthash/

### 3.2 Implémentation détaillée de la whitelist

```c
/* whitelist.h */
#ifndef WHITELIST_H
#define WHITELIST_H

#include "uthash.h"
#include <stdbool.h>
#include <stdint.h>
#include <limits.h>

/*
 * Structure représentant une entrée de whitelist
 * 
 * Une entrée peut avoir plusieurs attributs :
 * - Le chemin (clé primaire)
 * - Les processus autorisés (optionnel)
 * - Les opérations autorisées (lecture, écriture, exécution)
 * - Un commentaire/raison pour l'audit
 */
typedef struct whitelist_entry {
    /* Clé de la hash table - DOIT être un pointeur ou tableau inline */
    char path[PATH_MAX];
    
    /* Masque d'opérations autorisées */
    uint64_t allowed_operations;
    
    /* Liste optionnelle de PIDs autorisés (NULL = tous) */
    pid_t *allowed_pids;
    size_t allowed_pids_count;
    
    /* Liste optionnelle de noms de processus autorisés */
    char **allowed_process_names;
    size_t allowed_process_names_count;
    
    /* Métadonnées pour logging/audit */
    char *comment;
    time_t added_at;
    
    /* Handle uthash - OBLIGATOIRE pour que uthash fonctionne */
    UT_hash_handle hh;
    
} whitelist_entry_t;

/* Opérations possibles (bitmask) */
#define OP_READ     (1 << 0)
#define OP_WRITE    (1 << 1)
#define OP_EXECUTE  (1 << 2)
#define OP_DELETE   (1 << 3)
#define OP_ALL      (OP_READ | OP_WRITE | OP_EXECUTE | OP_DELETE)

/*
 * Contexte de la whitelist
 * Encapsule la hash table et les statistiques
 */
typedef struct whitelist_ctx {
    whitelist_entry_t *entries;  /* Pointeur vers la hash table (NULL = vide) */
    size_t count;                /* Nombre d'entrées */
    pthread_rwlock_t lock;       /* Lock pour accès concurrent */
} whitelist_ctx_t;

/* API publique */
whitelist_ctx_t *whitelist_create(void);
void whitelist_destroy(whitelist_ctx_t *ctx);

int whitelist_add(whitelist_ctx_t *ctx, const char *path, 
                  uint64_t operations, const char *comment);
int whitelist_remove(whitelist_ctx_t *ctx, const char *path);
whitelist_entry_t *whitelist_lookup(whitelist_ctx_t *ctx, const char *path);
bool whitelist_check(whitelist_ctx_t *ctx, const char *path, uint64_t operation);

int whitelist_load_from_file(whitelist_ctx_t *ctx, const char *filepath);
int whitelist_save_to_file(whitelist_ctx_t *ctx, const char *filepath);

#endif /* WHITELIST_H */
```

```c
/* whitelist.c */
#include "whitelist.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

/*
 * whitelist_create - Crée un nouveau contexte de whitelist
 * 
 * Pourquoi un contexte plutôt qu'une variable globale ?
 * - Permet d'avoir plusieurs whitelists (ex: une par niveau de sécurité)
 * - Facilite les tests unitaires
 * - Thread-safety plus claire
 */
whitelist_ctx_t *whitelist_create(void) {
    whitelist_ctx_t *ctx = calloc(1, sizeof(whitelist_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }
    
    /* Initialiser le rwlock pour accès concurrent
     * 
     * Pourquoi un rwlock et pas un mutex ?
     * - Les lookups sont BEAUCOUP plus fréquents que les modifications
     * - Plusieurs threads peuvent lire simultanément (rwlock)
     * - Un mutex bloquerait tous les readers inutilement
     */
    if (pthread_rwlock_init(&ctx->lock, NULL) != 0) {
        free(ctx);
        return NULL;
    }
    
    ctx->entries = NULL;  /* uthash utilise NULL pour une table vide */
    ctx->count = 0;
    
    return ctx;
}

/*
 * whitelist_destroy - Libère toutes les ressources
 * 
 * ATTENTION : Ne pas appeler pendant que d'autres threads utilisent la whitelist
 */
void whitelist_destroy(whitelist_ctx_t *ctx) {
    if (ctx == NULL) return;
    
    /* Acquérir le write lock pour s'assurer que personne ne lit */
    pthread_rwlock_wrlock(&ctx->lock);
    
    /* Parcourir et libérer toutes les entrées */
    whitelist_entry_t *entry, *tmp;
    HASH_ITER(hh, ctx->entries, entry, tmp) {
        HASH_DEL(ctx->entries, entry);
        
        /* Libérer les sous-structures */
        if (entry->allowed_pids != NULL) {
            free(entry->allowed_pids);
        }
        if (entry->allowed_process_names != NULL) {
            for (size_t i = 0; i < entry->allowed_process_names_count; i++) {
                free(entry->allowed_process_names[i]);
            }
            free(entry->allowed_process_names);
        }
        if (entry->comment != NULL) {
            free(entry->comment);
        }
        free(entry);
    }
    
    pthread_rwlock_unlock(&ctx->lock);
    pthread_rwlock_destroy(&ctx->lock);
    free(ctx);
}

/*
 * whitelist_add - Ajoute une entrée à la whitelist
 * 
 * @param ctx       Contexte whitelist
 * @param path      Chemin à whitelister (sera copié)
 * @param operations Masque des opérations autorisées
 * @param comment   Commentaire optionnel pour audit (peut être NULL)
 * 
 * @return 0 si succès, -1 si erreur (errno positionné)
 * 
 * Complexité : O(1) amorti
 */
int whitelist_add(whitelist_ctx_t *ctx, const char *path, 
                  uint64_t operations, const char *comment) {
    
    if (ctx == NULL || path == NULL) {
        errno = EINVAL;
        return -1;
    }
    
    /* Vérifier la longueur du chemin */
    size_t path_len = strlen(path);
    if (path_len >= PATH_MAX) {
        errno = ENAMETOOLONG;
        return -1;
    }
    
    /* Acquérir le write lock */
    pthread_rwlock_wrlock(&ctx->lock);
    
    /* Vérifier si l'entrée existe déjà */
    whitelist_entry_t *existing = NULL;
    HASH_FIND_STR(ctx->entries, path, existing);
    if (existing != NULL) {
        /* Mettre à jour l'entrée existante au lieu d'en créer une nouvelle */
        existing->allowed_operations = operations;
        if (existing->comment != NULL) {
            free(existing->comment);
        }
        existing->comment = comment ? strdup(comment) : NULL;
        
        pthread_rwlock_unlock(&ctx->lock);
        return 0;
    }
    
    /* Créer une nouvelle entrée */
    whitelist_entry_t *entry = calloc(1, sizeof(whitelist_entry_t));
    if (entry == NULL) {
        pthread_rwlock_unlock(&ctx->lock);
        return -1;
    }
    
    /* Copier le chemin dans le buffer inline
     * 
     * Pourquoi un buffer inline plutôt qu'un pointeur ?
     * - uthash a besoin d'un buffer contigu pour la clé
     * - Évite une allocation supplémentaire
     * - Meilleure localité cache
     */
    strncpy(entry->path, path, PATH_MAX - 1);
    entry->path[PATH_MAX - 1] = '\0';
    
    entry->allowed_operations = operations;
    entry->comment = comment ? strdup(comment) : NULL;
    entry->added_at = time(NULL);
    
    /* Ajouter à la hash table
     * 
     * HASH_ADD_STR utilise le champ 'path' comme clé
     * Le dernier argument est le nom du champ UT_hash_handle
     */
    HASH_ADD_STR(ctx->entries, path, entry);
    ctx->count++;
    
    pthread_rwlock_unlock(&ctx->lock);
    return 0;
}

/*
 * whitelist_lookup - Recherche une entrée par chemin exact
 * 
 * @param ctx   Contexte whitelist
 * @param path  Chemin à rechercher
 * 
 * @return Pointeur vers l'entrée si trouvée, NULL sinon
 * 
 * ATTENTION : L'entrée retournée reste valide tant que le read lock est tenu
 *             par l'appelant ou tant qu'aucune modification n'est faite.
 *             Pour un usage sûr en multi-thread, copier les données nécessaires.
 * 
 * Complexité : O(1) amorti
 */
whitelist_entry_t *whitelist_lookup(whitelist_ctx_t *ctx, const char *path) {
    if (ctx == NULL || path == NULL) {
        return NULL;
    }
    
    /* Acquérir le read lock
     * 
     * Plusieurs threads peuvent avoir le read lock simultanément,
     * permettant des lookups parallèles efficaces.
     */
    pthread_rwlock_rdlock(&ctx->lock);
    
    whitelist_entry_t *entry = NULL;
    HASH_FIND_STR(ctx->entries, path, entry);
    
    pthread_rwlock_unlock(&ctx->lock);
    return entry;
}

/*
 * whitelist_check - Vérifie si un accès est autorisé
 * 
 * @param ctx       Contexte whitelist
 * @param path      Chemin accédé
 * @param operation Opération tentée (OP_READ, OP_WRITE, etc.)
 * 
 * @return true si autorisé, false sinon
 * 
 * Cette fonction est le point d'entrée principal pour la vérification.
 * Elle combine le lookup et la vérification des permissions.
 */
bool whitelist_check(whitelist_ctx_t *ctx, const char *path, uint64_t operation) {
    whitelist_entry_t *entry = whitelist_lookup(ctx, path);
    
    if (entry == NULL) {
        return false;  /* Non trouvé = non autorisé */
    }
    
    /* Vérifier si l'opération est autorisée */
    return (entry->allowed_operations & operation) == operation;
}

/*
 * whitelist_load_from_file - Charge la whitelist depuis un fichier
 * 
 * Format attendu du fichier (une entrée par ligne) :
 * 
 * # Commentaires commencent par #
 * /etc/passwd  rwx  "Fichier utilisateurs système"
 * /etc/shadow  r    "Hash des mots de passe"
 * /var/log/    rw   "Répertoire logs"
 * 
 * Les opérations : r=read, w=write, x=execute, d=delete
 */
int whitelist_load_from_file(whitelist_ctx_t *ctx, const char *filepath) {
    FILE *fp = fopen(filepath, "r");
    if (fp == NULL) {
        return -1;
    }
    
    char line[1024];
    int line_num = 0;
    
    while (fgets(line, sizeof(line), fp) != NULL) {
        line_num++;
        
        /* Ignorer les lignes vides et commentaires */
        char *trimmed = line;
        while (*trimmed == ' ' || *trimmed == '\t') trimmed++;
        if (*trimmed == '#' || *trimmed == '\n' || *trimmed == '\0') {
            continue;
        }
        
        /* Parser la ligne */
        char path[PATH_MAX];
        char ops[32];
        char comment[256] = "";
        
        /* Format: path operations "comment" */
        int parsed = sscanf(trimmed, "%s %31s \"%255[^\"]\"", path, ops, comment);
        if (parsed < 2) {
            fprintf(stderr, "Whitelist: Erreur de syntaxe ligne %d\n", line_num);
            continue;
        }
        
        /* Convertir les opérations en bitmask */
        uint64_t operations = 0;
        for (char *p = ops; *p; p++) {
            switch (*p) {
                case 'r': case 'R': operations |= OP_READ; break;
                case 'w': case 'W': operations |= OP_WRITE; break;
                case 'x': case 'X': operations |= OP_EXECUTE; break;
                case 'd': case 'D': operations |= OP_DELETE; break;
                default:
                    fprintf(stderr, "Whitelist: Opération inconnue '%c' ligne %d\n", 
                            *p, line_num);
            }
        }
        
        /* Ajouter l'entrée */
        if (whitelist_add(ctx, path, operations, 
                          comment[0] ? comment : NULL) != 0) {
            fprintf(stderr, "Whitelist: Erreur ajout '%s' ligne %d\n", 
                    path, line_num);
        }
    }
    
    fclose(fp);
    return 0;
}
```

### 3.3 Analyse de la complexité

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ OPÉRATION            │ COMPLEXITÉ      │ EXPLICATION                        │
├─────────────────────────────────────────────────────────────────────────────┤
│ whitelist_add        │ O(1) amorti     │ Hash du chemin + insertion         │
│                      │                 │ Pire cas O(n) si rehash nécessaire │
├─────────────────────────────────────────────────────────────────────────────┤
│ whitelist_lookup     │ O(1) amorti     │ Hash du chemin + lookup            │
│                      │                 │ Pire cas O(n) si collisions        │
├─────────────────────────────────────────────────────────────────────────────┤
│ whitelist_remove     │ O(1) amorti     │ Hash + suppression                 │
├─────────────────────────────────────────────────────────────────────────────┤
│ whitelist_load       │ O(k)            │ k = nombre d'entrées dans fichier  │
├─────────────────────────────────────────────────────────────────────────────┤
│ Mémoire par entrée   │ ~300-500 bytes  │ PATH_MAX(4096) + overhead uthash   │
│                      │                 │ Optimisable avec chemins plus      │
│                      │                 │ courts ou allocation dynamique     │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Implémentation avec Trie pour correspondance par préfixe

### 4.1 Pourquoi un Trie ?

La hash table ne suffit pas pour les règles avec wildcards :

```
Règle : "/etc/*" → Surveiller tout le répertoire /etc/

Hash table ne peut PAS matcher :
  - "/etc/passwd"  (pas égal à "/etc/*")
  - "/etc/shadow"  (pas égal à "/etc/*")

Il faut une structure qui supporte la correspondance par préfixe.
```

### 4.2 Concept du Trie

```
Un Trie (aussi appelé arbre préfixe) stocke les chaînes caractère par caractère :

Entrées : "/etc/", "/etc/passwd", "/var/log/"

                    (root)
                      │
                      ▼
                    '/' ─────────────────────────┐
                      │                          │
                      ▼                          ▼
                    'e'                        'v'
                      │                          │
                      ▼                          ▼
                    't'                        'a'
                      │                          │
                      ▼                          ▼
                    'c'                        'r'
                      │                          │
                      ▼                          ▼
                    '/' ★ (terminal: règle "/etc/")
                      │                          │
                      ▼                          ▼
                    'p'                        '/'
                      │                          │
                      ▼                          ▼
                    'a'                        'l'
                      │                          │
                      ▼                          ▼
                    's'                        'o'
                      │                          │
                      ▼                          ▼
                    's'                        'g'
                      │                          │
                      ▼                          ▼
                    'w'                        '/'  ★ (terminal: règle "/var/log/")
                      │
                      ▼
                    'd' ★ (terminal: règle "/etc/passwd")

Lookup de "/etc/passwd" :
  1. Parcourir : / → e → t → c → / → p → a → s → s → w → d
  2. Trouver tous les nœuds terminaux sur le chemin
  3. Résultat : "/etc/" et "/etc/passwd" matchent tous les deux

Cela permet d'appliquer la règle la plus spécifique ou les deux.
```

### 4.3 Implémentation du Trie

```c
/* trie.h */
#ifndef TRIE_H
#define TRIE_H

#include <stdbool.h>
#include <stdint.h>

/*
 * Structure d'un nœud du Trie
 * 
 * Chaque nœud représente un caractère du chemin.
 * children[c] pointe vers le nœud pour le caractère c.
 */
typedef struct trie_node {
    /* Tableau des enfants (un pour chaque caractère ASCII possible)
     * 
     * Pourquoi 128 et pas 256 ?
     * - Les chemins filesystem utilisent uniquement ASCII imprimable
     * - Économise de la mémoire
     * - Si besoin d'UTF-8, utiliser une autre implémentation
     */
    struct trie_node *children[128];
    
    /* Ce nœud est-il la fin d'une règle ? */
    bool is_terminal;
    
    /* Si terminal, données associées à cette règle */
    void *data;
    
    /* Compteur d'enfants (pour optimiser la suppression) */
    int child_count;
    
} trie_node_t;

/*
 * Structure du Trie complet
 */
typedef struct trie {
    trie_node_t *root;
    size_t entry_count;
    pthread_rwlock_t lock;
} trie_t;

/*
 * Résultat d'une recherche de préfixe
 * Peut retourner plusieurs correspondances (la plus longue et ses ancêtres)
 */
typedef struct trie_match {
    const char *matched_prefix;  /* Le préfixe qui a matché */
    void *data;                  /* Données associées */
    size_t prefix_length;        /* Longueur du préfixe */
} trie_match_t;

typedef struct trie_match_result {
    trie_match_t *matches;       /* Tableau de correspondances */
    size_t count;                /* Nombre de correspondances */
    size_t capacity;             /* Capacité allouée */
} trie_match_result_t;

/* API publique */
trie_t *trie_create(void);
void trie_destroy(trie_t *trie);

int trie_insert(trie_t *trie, const char *key, void *data);
int trie_remove(trie_t *trie, const char *key);

/* Recherche exacte */
void *trie_search_exact(trie_t *trie, const char *key);

/* Recherche du préfixe le plus long qui matche */
trie_match_t trie_search_longest_prefix(trie_t *trie, const char *key);

/* Recherche de TOUS les préfixes qui matchent */
trie_match_result_t *trie_search_all_prefixes(trie_t *trie, const char *key);
void trie_match_result_free(trie_match_result_t *result);

#endif /* TRIE_H */
```

```c
/* trie.c */
#include "trie.h"
#include <stdlib.h>
#include <string.h>

/*
 * Création d'un nouveau nœud
 * 
 * Tous les pointeurs enfants sont initialisés à NULL.
 * Un nœud consomme environ 128 * 8 = 1024 bytes (sur 64-bit).
 * 
 * Optimisation possible : Utiliser un tableau compressé ou une hash table
 * par nœud pour réduire la mémoire.
 */
static trie_node_t *trie_node_create(void) {
    trie_node_t *node = calloc(1, sizeof(trie_node_t));
    return node;  /* calloc initialise tout à 0/NULL */
}

/*
 * Destruction récursive d'un nœud et de ses enfants
 */
static void trie_node_destroy(trie_node_t *node) {
    if (node == NULL) return;
    
    for (int i = 0; i < 128; i++) {
        if (node->children[i] != NULL) {
            trie_node_destroy(node->children[i]);
        }
    }
    
    /* Note : on ne libère PAS node->data, c'est la responsabilité de l'appelant */
    free(node);
}

trie_t *trie_create(void) {
    trie_t *trie = calloc(1, sizeof(trie_t));
    if (trie == NULL) return NULL;
    
    trie->root = trie_node_create();
    if (trie->root == NULL) {
        free(trie);
        return NULL;
    }
    
    if (pthread_rwlock_init(&trie->lock, NULL) != 0) {
        trie_node_destroy(trie->root);
        free(trie);
        return NULL;
    }
    
    return trie;
}

void trie_destroy(trie_t *trie) {
    if (trie == NULL) return;
    
    pthread_rwlock_wrlock(&trie->lock);
    trie_node_destroy(trie->root);
    pthread_rwlock_unlock(&trie->lock);
    pthread_rwlock_destroy(&trie->lock);
    free(trie);
}

/*
 * trie_insert - Insère une clé dans le Trie
 * 
 * Parcourt le chemin caractère par caractère, créant les nœuds manquants.
 * Marque le dernier nœud comme terminal.
 * 
 * Complexité : O(m) où m = longueur de la clé
 */
int trie_insert(trie_t *trie, const char *key, void *data) {
    if (trie == NULL || key == NULL) return -1;
    
    pthread_rwlock_wrlock(&trie->lock);
    
    trie_node_t *current = trie->root;
    
    for (const char *p = key; *p != '\0'; p++) {
        unsigned char c = (unsigned char)*p;
        
        /* Vérifier que le caractère est dans la plage supportée */
        if (c >= 128) {
            pthread_rwlock_unlock(&trie->lock);
            return -1;  /* Caractère non-ASCII non supporté */
        }
        
        /* Créer le nœud enfant s'il n'existe pas */
        if (current->children[c] == NULL) {
            current->children[c] = trie_node_create();
            if (current->children[c] == NULL) {
                pthread_rwlock_unlock(&trie->lock);
                return -1;  /* Échec d'allocation */
            }
            current->child_count++;
        }
        
        current = current->children[c];
    }
    
    /* Marquer le nœud final comme terminal */
    current->is_terminal = true;
    current->data = data;
    trie->entry_count++;
    
    pthread_rwlock_unlock(&trie->lock);
    return 0;
}

/*
 * trie_search_longest_prefix - Trouve le préfixe le plus long qui matche
 * 
 * Exemple :
 *   Trie contient : "/etc/", "/etc/passwd", "/var/"
 *   Recherche de "/etc/shadow" :
 *   → Parcourt : / → e → t → c → /
 *   → "/etc/" est terminal, on le mémorise
 *   → Continue : s → h → a → d → o → w
 *   → Pas de nœud pour 's' après "/etc/"
 *   → Retourne le dernier terminal trouvé : "/etc/"
 * 
 * Complexité : O(m) où m = longueur de la clé
 */
trie_match_t trie_search_longest_prefix(trie_t *trie, const char *key) {
    trie_match_t result = {0};
    
    if (trie == NULL || key == NULL) return result;
    
    pthread_rwlock_rdlock(&trie->lock);
    
    trie_node_t *current = trie->root;
    const char *last_terminal_pos = NULL;
    void *last_terminal_data = NULL;
    
    for (const char *p = key; *p != '\0'; p++) {
        unsigned char c = (unsigned char)*p;
        
        if (c >= 128 || current->children[c] == NULL) {
            /* Pas de continuation possible */
            break;
        }
        
        current = current->children[c];
        
        /* Si ce nœud est terminal, mémoriser comme meilleur match jusqu'ici */
        if (current->is_terminal) {
            last_terminal_pos = p + 1;  /* Position juste après ce caractère */
            last_terminal_data = current->data;
        }
    }
    
    if (last_terminal_pos != NULL) {
        result.matched_prefix = key;  /* Le préfixe commence au début de key */
        result.prefix_length = last_terminal_pos - key;
        result.data = last_terminal_data;
    }
    
    pthread_rwlock_unlock(&trie->lock);
    return result;
}

/*
 * trie_search_all_prefixes - Trouve TOUS les préfixes qui matchent
 * 
 * Utile quand on veut appliquer des règles cumulatives.
 * Exemple : "/etc/" peut avoir des règles générales,
 *           "/etc/passwd" peut avoir des règles spécifiques
 *           → On veut les deux
 */
trie_match_result_t *trie_search_all_prefixes(trie_t *trie, const char *key) {
    trie_match_result_t *result = calloc(1, sizeof(trie_match_result_t));
    if (result == NULL) return NULL;
    
    result->capacity = 8;  /* Allocation initiale */
    result->matches = calloc(result->capacity, sizeof(trie_match_t));
    if (result->matches == NULL) {
        free(result);
        return NULL;
    }
    
    if (trie == NULL || key == NULL) return result;
    
    pthread_rwlock_rdlock(&trie->lock);
    
    trie_node_t *current = trie->root;
    
    for (const char *p = key; *p != '\0'; p++) {
        unsigned char c = (unsigned char)*p;
        
        if (c >= 128 || current->children[c] == NULL) {
            break;
        }
        
        current = current->children[c];
        
        if (current->is_terminal) {
            /* Agrandir le tableau si nécessaire */
            if (result->count >= result->capacity) {
                result->capacity *= 2;
                trie_match_t *new_matches = realloc(result->matches,
                    result->capacity * sizeof(trie_match_t));
                if (new_matches == NULL) {
                    break;  /* Continuer avec ce qu'on a */
                }
                result->matches = new_matches;
            }
            
            /* Ajouter cette correspondance */
            result->matches[result->count].matched_prefix = key;
            result->matches[result->count].prefix_length = (p + 1) - key;
            result->matches[result->count].data = current->data;
            result->count++;
        }
    }
    
    pthread_rwlock_unlock(&trie->lock);
    return result;
}

void trie_match_result_free(trie_match_result_t *result) {
    if (result == NULL) return;
    free(result->matches);
    free(result);
}
```

---

## 5. Système hybride haute performance

### 5.1 Combiner Hash Table et Trie

```c
/* policy_engine.h */
#ifndef POLICY_ENGINE_H
#define POLICY_ENGINE_H

#include "whitelist.h"
#include "trie.h"

/*
 * Structure de règle unifiée
 * Utilisée pour les entrées exactes et les préfixes
 */
typedef struct policy_rule {
    char *path;                 /* Chemin ou préfixe */
    bool is_prefix;             /* true si c'est un préfixe (finit par /) */
    uint64_t allowed_ops;       /* Opérations autorisées */
    int security_level;         /* Niveau minimum requis pour cette règle */
    char *comment;
} policy_rule_t;

/*
 * Moteur de politique combinant toutes les structures
 */
typedef struct policy_engine {
    /* Hash tables pour lookups exacts O(1) */
    whitelist_ctx_t *whitelist_exact;
    whitelist_ctx_t *blacklist_exact;
    
    /* Tries pour correspondance par préfixe O(m) */
    trie_t *whitelist_prefix;
    trie_t *blacklist_prefix;
    
    /* Configuration globale */
    int current_security_level;
    bool default_deny;  /* Si true, non-whitelisté = refusé */
    
    /* Statistiques */
    uint64_t total_checks;
    uint64_t whitelist_hits;
    uint64_t blacklist_hits;
    uint64_t denied_count;
    
} policy_engine_t;

typedef enum {
    POLICY_ALLOW,
    POLICY_DENY,
    POLICY_LOG_ONLY,
    POLICY_ALERT
} policy_decision_t;

/* API */
policy_engine_t *policy_engine_create(void);
void policy_engine_destroy(policy_engine_t *engine);

int policy_engine_load_config(policy_engine_t *engine, const char *config_path);
int policy_engine_reload(policy_engine_t *engine);

policy_decision_t policy_engine_check(policy_engine_t *engine,
                                      const char *path,
                                      uint64_t operation,
                                      pid_t pid);

#endif /* POLICY_ENGINE_H */
```

```c
/* policy_engine.c */
#include "policy_engine.h"
#include <syslog.h>

/*
 * Algorithme de décision principal
 * 
 * ORDRE DES VÉRIFICATIONS :
 * 
 * 1. Blacklist exacte (priorité maximale)
 * 2. Blacklist préfixe
 * 3. Whitelist exacte
 * 4. Whitelist préfixe (la plus longue)
 * 5. Décision par défaut (selon security_level)
 */
policy_decision_t policy_engine_check(policy_engine_t *engine,
                                      const char *path,
                                      uint64_t operation,
                                      pid_t pid) {
    if (engine == NULL || path == NULL) {
        return POLICY_DENY;
    }
    
    engine->total_checks++;
    
    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
    /* ÉTAPE 1 : Vérifier la blacklist exacte                               */
    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
    
    whitelist_entry_t *bl_exact = whitelist_lookup(engine->blacklist_exact, path);
    if (bl_exact != NULL) {
        engine->blacklist_hits++;
        syslog(LOG_WARNING, "HIDS: Blacklist exact match: %s (PID %d)", 
               path, pid);
        return POLICY_DENY;
    }
    
    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
    /* ÉTAPE 2 : Vérifier la blacklist par préfixe                          */
    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
    
    trie_match_t bl_prefix = trie_search_longest_prefix(engine->blacklist_prefix, 
                                                         path);
    if (bl_prefix.data != NULL) {
        policy_rule_t *rule = (policy_rule_t *)bl_prefix.data;
        
        /* Vérifier si l'opération spécifique est blacklistée */
        if (rule->allowed_ops == 0 || (rule->allowed_ops & operation)) {
            engine->blacklist_hits++;
            syslog(LOG_WARNING, "HIDS: Blacklist prefix match: %.*s* for %s (PID %d)",
                   (int)bl_prefix.prefix_length, path, path, pid);
            return POLICY_DENY;
        }
    }
    
    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
    /* ÉTAPE 3 : Vérifier la whitelist exacte                               */
    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
    
    whitelist_entry_t *wl_exact = whitelist_lookup(engine->whitelist_exact, path);
    if (wl_exact != NULL) {
        /* Vérifier que l'opération est autorisée */
        if (wl_exact->allowed_operations & operation) {
            engine->whitelist_hits++;
            return POLICY_ALLOW;
        }
        /* Opération non autorisée pour ce fichier whitelisté */
        syslog(LOG_NOTICE, "HIDS: Operation %lu not allowed for whitelisted %s",
               operation, path);
    }
    
    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
    /* ÉTAPE 4 : Vérifier la whitelist par préfixe                          */
    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
    
    trie_match_t wl_prefix = trie_search_longest_prefix(engine->whitelist_prefix,
                                                         path);
    if (wl_prefix.data != NULL) {
        policy_rule_t *rule = (policy_rule_t *)wl_prefix.data;
        
        if (rule->allowed_ops & operation) {
            engine->whitelist_hits++;
            return POLICY_ALLOW;
        }
    }
    
    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
    /* ÉTAPE 5 : Décision par défaut                                        */
    /* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */
    
    /* Accès ni blacklisté ni whitelisté explicitement */
    
    if (engine->default_deny) {
        /* Mode paranoïaque : tout ce qui n'est pas whitelisté est refusé */
        syslog(LOG_NOTICE, "HIDS: Unknown path denied (default deny): %s", path);
        engine->denied_count++;
        return POLICY_DENY;
    }
    
    /* Mode permissif : logger et autoriser */
    switch (engine->current_security_level) {
        case 0:
        case 1:
        case 2:
            /* Log silencieux */
            return POLICY_LOG_ONLY;
            
        case 3:
        case 4:
        case 5:
            /* Générer une alerte mais autoriser */
            syslog(LOG_NOTICE, "HIDS: Unknown path accessed: %s by PID %d",
                   path, pid);
            return POLICY_ALERT;
            
        default:
            /* Niveaux élevés : comportement conservateur */
            return POLICY_ALERT;
    }
}
```

### 5.2 Optimisation avec Bloom Filter (optionnel)

Pour des listes très grandes (>10000 entrées), un Bloom filter peut accélérer les rejets :

```c
/*
 * Bloom Filter : Structure probabiliste pour test d'appartenance
 * 
 * Propriétés :
 * - "Élément absent" → CERTAIN qu'il est absent
 * - "Élément présent" → PROBABLE qu'il est présent (faux positifs possibles)
 * 
 * Pour un HIDS :
 * - Utilisé comme pré-filtre rapide
 * - Si le Bloom dit "absent de la blacklist" → pas besoin de vérifier
 * - Si le Bloom dit "peut-être présent" → vérifier dans la vraie structure
 */

#include <stdint.h>
#include <stdbool.h>

typedef struct bloom_filter {
    uint8_t *bits;
    size_t size_bits;
    int num_hashes;
} bloom_filter_t;

/* Fonctions de hash pour Bloom filter */
static uint64_t hash1(const char *str) {
    /* FNV-1a hash */
    uint64_t hash = 14695981039346656037ULL;
    while (*str) {
        hash ^= (uint8_t)*str++;
        hash *= 1099511628211ULL;
    }
    return hash;
}

static uint64_t hash2(const char *str) {
    /* DJB2 hash */
    uint64_t hash = 5381;
    while (*str) {
        hash = ((hash << 5) + hash) + (uint8_t)*str++;
    }
    return hash;
}

void bloom_add(bloom_filter_t *bf, const char *key) {
    uint64_t h1 = hash1(key);
    uint64_t h2 = hash2(key);
    
    for (int i = 0; i < bf->num_hashes; i++) {
        uint64_t idx = (h1 + i * h2) % bf->size_bits;
        bf->bits[idx / 8] |= (1 << (idx % 8));
    }
}

bool bloom_check(bloom_filter_t *bf, const char *key) {
    uint64_t h1 = hash1(key);
    uint64_t h2 = hash2(key);
    
    for (int i = 0; i < bf->num_hashes; i++) {
        uint64_t idx = (h1 + i * h2) % bf->size_bits;
        if (!(bf->bits[idx / 8] & (1 << (idx % 8)))) {
            return false;  /* Certainement absent */
        }
    }
    return true;  /* Probablement présent */
}

/*
 * Intégration dans policy_engine_check :
 */
policy_decision_t optimized_check(policy_engine_t *engine, const char *path, ...) {
    
    /* Pré-filtre ultra-rapide avec Bloom filter */
    if (!bloom_check(&engine->blacklist_bloom, path)) {
        /* Certainement pas dans la blacklist → skip vérification complète */
        /* Passer directement à la whitelist */
    } else {
        /* Peut-être dans la blacklist → vérifier pour de vrai */
        /* ... vérification normale ... */
    }
    
    /* ... reste de la logique ... */
}
```

---

## Résumé des points clés de cette partie

1. **Architecture modulaire** : Séparez configuration, moteur de politique, traitement d'événements et logging

2. **Priorité des règles** : Blacklist > Whitelist > Règles par défaut

3. **Structures de données** :
   - Hash table (uthash) pour les chemins exacts — O(1)
   - Trie pour les préfixes — O(m)
   - Optionnel : Bloom filter pour pré-filtrage — O(k)

4. **Thread-safety** : Utilisez des rwlocks pour permettre les lectures parallèles

5. **Fichiers critiques** : Priorisez authentification, SSH, persistance, binaires système, logs

---

## Références

- uthash : https://troydhanson.github.io/uthash/
- Benchmark hash tables C/C++ : https://jacksonallan.github.io/c_cpp_hash_tables_benchmark/
- OSSEC file integrity monitoring : https://www.ossec.net/docs/
- CIS Benchmarks : https://www.cisecurity.org/cis-benchmarks
