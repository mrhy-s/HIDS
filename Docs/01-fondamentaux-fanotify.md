# Guide HIDS en C avec fanotify — Partie 1 : Fondamentaux de l'API fanotify

## Table des matières
1. [Qu'est-ce que fanotify et pourquoi l'utiliser](#1-quest-ce-que-fanotify-et-pourquoi-lutiliser)
2. [Architecture interne de fanotify](#2-architecture-interne-de-fanotify)
3. [Les classes de notification en détail](#3-les-classes-de-notification-en-détail)
4. [Structures de données fondamentales](#4-structures-de-données-fondamentales)
5. [Le mécanisme de permission events](#5-le-mécanisme-de-permission-events)

---

## 1. Qu'est-ce que fanotify et pourquoi l'utiliser

### 1.1 Contexte historique

fanotify (Filesystem-wide Access Notification) a été introduit dans le **kernel Linux 2.6.36** (2010) et activé par défaut dans la version 2.6.37. Cette API a été conçue spécifiquement pour répondre aux besoins des **scanners antivirus** et des **systèmes de détection d'intrusion**.

Avant fanotify, les développeurs utilisaient **inotify** (introduit en 2005), qui présentait une limitation majeure : il ne pouvait que **notifier** les événements *après* leur occurrence. Impossible donc de bloquer un accès malveillant avant qu'il ne se produise.

### 1.2 La différence fondamentale avec inotify

Pour bien comprendre pourquoi fanotify est essentiel pour un HIDS, comparons les deux APIs :

```
┌─────────────────────────────────────────────────────────────────┐
│                         INOTIFY                                  │
├─────────────────────────────────────────────────────────────────┤
│  Processus        Kernel           Votre HIDS                   │
│     │                │                  │                       │
│     │── open() ────▶│                  │                       │
│     │               │── FICHIER OUVERT │                       │
│     │◀── fd ────────│                  │                       │
│     │               │                  │                       │
│     │               │── notification ─▶│  "Le fichier a été    │
│     │               │   (APRÈS coup)   │   ouvert"             │
│     │               │                  │  (trop tard pour      │
│     │               │                  │   bloquer!)           │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                        FANOTIFY                                  │
├─────────────────────────────────────────────────────────────────┤
│  Processus        Kernel           Votre HIDS                   │
│     │                │                  │                       │
│     │── open() ────▶│                  │                       │
│     │               │── PROCESSUS      │                       │
│     │               │   BLOQUÉ ────────│                       │
│     │               │                  │                       │
│     │               │── permission ───▶│  "Processus X veut    │
│     │               │   request        │   ouvrir fichier Y"   │
│     │               │                  │                       │
│     │               │                  │── Analyse...          │
│     │               │                  │                       │
│     │               │◀─ FAN_ALLOW ─────│  ou FAN_DENY          │
│     │               │   ou FAN_DENY    │                       │
│     │               │                  │                       │
│     │◀── fd ────────│  (si ALLOW)      │                       │
│     │   ou EPERM    │  (si DENY)       │                       │
└─────────────────────────────────────────────────────────────────┘
```

**Source** : man7.org/linux/man-pages/man7/fanotify.7.html

### 1.3 Cas d'utilisation concrets pour un HIDS

fanotify est particulièrement adapté pour :

1. **Surveillance d'intégrité en temps réel** : Détecter immédiatement toute modification de fichiers critiques (`/etc/passwd`, `/etc/shadow`, etc.)

2. **Contrôle d'exécution** : Avec `FAN_OPEN_EXEC_PERM` (Linux 5.0+), bloquer l'exécution de binaires non autorisés

3. **Scan antivirus on-access** : Scanner le contenu d'un fichier *avant* qu'il ne soit accessible au processus demandeur

4. **Détection de comportements suspects** : Identifier des patterns d'accès anormaux (ex: processus accédant massivement à `/etc/`)

### 1.4 Prérequis système

Pour utiliser fanotify avec les permission events (indispensables pour un HIDS), vous devez :

```c
/* Vérifier que le kernel supporte fanotify */
// Le kernel doit être compilé avec :
// - CONFIG_FANOTIFY=y           (notifications basiques)
// - CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y  (permission events)

/* Vérifier les capabilities requises */
// Pour FAN_CLASS_CONTENT ou FAN_CLASS_PRE_CONTENT :
// - CAP_SYS_ADMIN est OBLIGATOIRE

/* Vérifier la version du kernel pour les fonctionnalités avancées */
// Linux 5.0+  : FAN_OPEN_EXEC_PERM (contrôle d'exécution)
// Linux 5.1+  : FAN_REPORT_FID (file handles au lieu de fd)
// Linux 5.9+  : FAN_REPORT_DIR_FID, FAN_REPORT_NAME
// Linux 5.13+ : fanotify sans CAP_SYS_ADMIN (fonctionnalités limitées)
// Linux 5.15+ : FAN_REPORT_PIDFD (PID file descriptor)
// Linux 6.13+ : FAN_DENY_ERRNO(e) (erreurs personnalisées)
```

---

## 2. Architecture interne de fanotify

### 2.1 Le concept de "fanotify group"

Quand vous appelez `fanotify_init()`, le kernel crée un **fanotify group** — une structure interne qui représente votre "abonnement" aux événements filesystem.

```
┌──────────────────────────────────────────────────────────────────┐
│                    ESPACE UTILISATEUR                             │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│   Votre HIDS                                                      │
│   ┌─────────────────────────────────────────────────────────┐    │
│   │  int fd = fanotify_init(flags, event_f_flags);          │    │
│   │                                                          │    │
│   │  // fd est un file descriptor spécial                   │    │
│   │  // Il représente votre connexion au groupe fanotify    │    │
│   └─────────────────────────────────────────────────────────┘    │
│                           │                                       │
│                           │ fd                                    │
│                           ▼                                       │
├──────────────────────────────────────────────────────────────────┤
│                      ESPACE KERNEL                                │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│   ┌─────────────────────────────────────────────────────────┐    │
│   │              FANOTIFY GROUP                              │    │
│   │  ┌─────────────────────────────────────────────────┐    │    │
│   │  │  Event Queue (file d'attente des événements)    │    │    │
│   │  │  - Limite par défaut : 16384 événements         │    │    │
│   │  │  - Peut être illimitée avec FAN_UNLIMITED_QUEUE │    │    │
│   │  └─────────────────────────────────────────────────┘    │    │
│   │                                                          │    │
│   │  ┌─────────────────────────────────────────────────┐    │    │
│   │  │  Mark List (liste des "marks" = points de       │    │    │
│   │  │  surveillance)                                   │    │    │
│   │  │  - Limite par défaut : 8192 marks               │    │    │
│   │  │  - Peut être illimitée avec FAN_UNLIMITED_MARKS │    │    │
│   │  └─────────────────────────────────────────────────┘    │    │
│   │                                                          │    │
│   │  ┌─────────────────────────────────────────────────┐    │    │
│   │  │  Permission Events Pending List                  │    │    │
│   │  │  (événements en attente de réponse)             │    │    │
│   │  └─────────────────────────────────────────────────┘    │    │
│   │                                                          │    │
│   │  Priority Class: PRE_CONTENT | CONTENT | NOTIF         │    │
│   └─────────────────────────────────────────────────────────┘    │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

### 2.2 Le système de "marks"

Un **mark** est un point de surveillance que vous placez sur un objet filesystem. Il existe trois types de marks :

```c
/* TYPE 1 : Mark sur un inode spécifique */
// Surveille UN fichier ou UN répertoire précis
fanotify_mark(fd, FAN_MARK_ADD,
              FAN_MODIFY | FAN_CLOSE_WRITE,
              AT_FDCWD, "/etc/passwd");
// Avantage : Précis, peu de "bruit"
// Inconvénient : Ne suit pas si le fichier est renommé/recréé


/* TYPE 2 : Mark sur un mount point */
// Surveille TOUS les fichiers d'un point de montage
fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
              FAN_OPEN_PERM | FAN_CLOSE_WRITE,
              AT_FDCWD, "/");
// Avantage : Capture tout, y compris nouveaux fichiers
// Inconvénient : Volume d'événements potentiellement énorme


/* TYPE 3 : Mark sur un filesystem (Linux 4.20+) */
// Surveille TOUTES les instances d'un filesystem
fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
              FAN_MODIFY,
              AT_FDCWD, "/home");
// Avantage : Fonctionne même si le FS est monté plusieurs fois
// Inconvénient : Encore plus d'événements
```

**Conseil pour un HIDS** : Utilisez une combinaison :
- `FAN_MARK_MOUNT` sur `/` pour les permission events (détection globale)
- `FAN_MARK_INODE` sur les fichiers critiques spécifiques pour le suivi d'intégrité

### 2.3 Flux de vie d'un événement

```
┌───────────────────────────────────────────────────────────────────────┐
│ 1. Un processus tente d'ouvrir /etc/shadow                            │
└───────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌───────────────────────────────────────────────────────────────────────┐
│ 2. Le VFS (Virtual File System) intercepte l'appel                    │
│    → Vérifie si un fanotify group surveille cet objet                │
│    → OUI : Un mark existe sur "/" avec FAN_OPEN_PERM                 │
└───────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌───────────────────────────────────────────────────────────────────────┐
│ 3. Le kernel crée une structure fanotify_event et l'ajoute à la      │
│    Event Queue du groupe                                              │
│    → Le processus demandeur est MIS EN ATTENTE                       │
└───────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌───────────────────────────────────────────────────────────────────────┐
│ 4. Votre HIDS fait read() sur le fd fanotify                         │
│    → Reçoit la structure fanotify_event_metadata                     │
│    → Contient : fd du fichier, PID du processus, type d'événement   │
└───────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌───────────────────────────────────────────────────────────────────────┐
│ 5. Votre HIDS analyse et décide                                       │
│    → Vérifie whitelist/blacklist                                     │
│    → Peut lire le contenu du fichier via le fd fourni                │
│    → Peut identifier le processus via /proc/PID/                     │
└───────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌───────────────────────────────────────────────────────────────────────┐
│ 6. Votre HIDS répond via write() sur le fd fanotify                  │
│    → Envoie struct fanotify_response {fd, FAN_ALLOW ou FAN_DENY}    │
└───────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌───────────────────────────────────────────────────────────────────────┐
│ 7. Le kernel réveille le processus en attente                         │
│    → Si FAN_ALLOW : l'open() réussit normalement                     │
│    → Si FAN_DENY : l'open() échoue avec errno = EPERM                │
└───────────────────────────────────────────────────────────────────────┘
```

---

## 3. Les classes de notification en détail

### 3.1 Comprendre les trois classes

Le paramètre `flags` de `fanotify_init()` détermine la **classe de notification** de votre groupe. Cette classe a deux impacts :

1. **Quels types d'événements vous pouvez recevoir**
2. **L'ordre de priorité si plusieurs listeners existent**

```c
/* CLASSE 1 : FAN_CLASS_NOTIF (défaut si rien spécifié) */
// - Reçoit UNIQUEMENT les événements informatifs (pas de permission)
// - Pas besoin de répondre aux événements
// - Priorité la plus basse
// - Utilisable depuis Linux 5.13 SANS CAP_SYS_ADMIN (avec restrictions)

int fd = fanotify_init(FAN_CLOEXEC | FAN_NONBLOCK, O_RDONLY);
// ATTENTION : Ne peut PAS utiliser FAN_OPEN_PERM, FAN_ACCESS_PERM, etc.


/* CLASSE 2 : FAN_CLASS_CONTENT */
// - Reçoit événements informatifs ET de permission
// - Le fichier est dans son état FINAL quand vous le recevez
// - Pensé pour les scanners antivirus (analyser contenu finalisé)
// - REQUIERT CAP_SYS_ADMIN
// - Priorité moyenne

int fd = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC, O_RDONLY);
// PEUT utiliser FAN_OPEN_PERM, FAN_ACCESS_PERM, FAN_OPEN_EXEC_PERM


/* CLASSE 3 : FAN_CLASS_PRE_CONTENT */
// - Reçoit événements informatifs ET de permission
// - Le fichier peut NE PAS être dans son état final
// - Pensé pour les HSM (Hierarchical Storage Management)
// - REQUIERT CAP_SYS_ADMIN
// - Priorité la plus haute

int fd = fanotify_init(FAN_CLASS_PRE_CONTENT | FAN_CLOEXEC, O_RDONLY);
// PEUT utiliser TOUT, y compris FAN_PRE_ACCESS (Linux 6.x)
```

### 3.2 L'ordre de notification entre listeners

Si plusieurs programmes utilisent fanotify sur les mêmes fichiers :

```
Ordre de réception des permission events :

1. FAN_CLASS_PRE_CONTENT  (tous les listeners de cette classe, ordre indéfini)
           │
           ▼
2. FAN_CLASS_CONTENT      (tous les listeners de cette classe, ordre indéfini)
           │
           ▼
3. FAN_CLASS_NOTIF        (notification seulement, pas de permission events)
```

**Implication pour votre HIDS** : Si vous voulez être le premier à décider, utilisez `FAN_CLASS_PRE_CONTENT`. Si vous voulez analyser le fichier dans son état final, utilisez `FAN_CLASS_CONTENT`.

### 3.3 Quelle classe choisir pour un HIDS ?

**Recommandation : `FAN_CLASS_CONTENT`**

Justification :
- Pour un HIDS, vous voulez généralement voir le fichier tel qu'il sera réellement utilisé (état final)
- `FAN_CLASS_PRE_CONTENT` est surtout utile si vous devez *modifier* le fichier avant qu'il soit lu (cas HSM)
- `FAN_CLASS_CONTENT` vous permet de scanner/hasher le contenu définitif

```c
/* Configuration recommandée pour un HIDS */
int fd = fanotify_init(
    FAN_CLASS_CONTENT |     /* Permission events, fichier dans état final */
    FAN_CLOEXEC |           /* Ferme automatiquement le fd sur exec() */
    FAN_NONBLOCK |          /* read() non-bloquant (pour event loop) */
    FAN_UNLIMITED_QUEUE |   /* Pas de limite sur la file d'événements */
    FAN_UNLIMITED_MARKS,    /* Pas de limite sur les marks */
    O_RDONLY | O_LARGEFILE  /* Flags pour les fd de fichiers reçus */
);
```

---

## 4. Structures de données fondamentales

### 4.1 fanotify_event_metadata : le cœur du système

Cette structure est ce que vous recevez quand vous faites `read()` sur le fd fanotify :

```c
struct fanotify_event_metadata {
    __u32 event_len;      /* Taille totale de cet événement en bytes */
    __u8 vers;            /* Version de la structure */
    __u8 reserved;        /* Réservé (padding) */
    __u16 metadata_len;   /* Taille de CETTE structure (sans les extras) */
    __aligned_u64 mask;   /* Bitmask décrivant l'événement */
    __s32 fd;             /* File descriptor du fichier concerné */
    __s32 pid;            /* PID du processus ayant déclenché l'événement */
};
```

Analysons chaque champ en détail :

#### event_len
```c
/* Pourquoi event_len existe-t-il ?
 * 
 * Depuis Linux 5.1, fanotify peut inclure des "information records"
 * additionnels après la structure de base. event_len vous dit la
 * taille TOTALE à consommer avant le prochain événement.
 *
 * Structure en mémoire :
 * 
 * ┌──────────────────────────────────┐
 * │  fanotify_event_metadata         │ ← metadata_len bytes
 * ├──────────────────────────────────┤
 * │  fanotify_event_info_fid         │ ← (optionnel, si FAN_REPORT_FID)
 * ├──────────────────────────────────┤
 * │  fanotify_event_info_pidfd       │ ← (optionnel, si FAN_REPORT_PIDFD)
 * └──────────────────────────────────┘
 *   ◄────────── event_len ──────────►
 */

/* Pour parcourir plusieurs événements dans un buffer : */
char buf[4096];
ssize_t len = read(fanotify_fd, buf, sizeof(buf));

struct fanotify_event_metadata *metadata = (struct fanotify_event_metadata *)buf;

while (FAN_EVENT_OK(metadata, len)) {
    /* Traiter metadata... */
    
    /* Passer à l'événement suivant */
    metadata = FAN_EVENT_NEXT(metadata, len);
}
```

#### vers
```c
/* Le champ vers doit TOUJOURS être vérifié !
 * 
 * Si le kernel a une version différente de vos headers, les structures
 * pourraient ne pas correspondre.
 */

if (metadata->vers != FANOTIFY_METADATA_VERSION) {
    fprintf(stderr, "Version fanotify incompatible: attendu %d, reçu %d\n",
            FANOTIFY_METADATA_VERSION, metadata->vers);
    exit(EXIT_FAILURE);
}
```

#### mask
```c
/* Le champ mask est un bitmask qui peut contenir plusieurs flags.
 * Voici les plus importants pour un HIDS :
 */

/* Événements informatifs (notification seulement) */
#define FAN_ACCESS        0x00000001  /* Fichier lu */
#define FAN_MODIFY        0x00000002  /* Fichier modifié */
#define FAN_CLOSE_WRITE   0x00000008  /* Fichier fermé après écriture */
#define FAN_CLOSE_NOWRITE 0x00000010  /* Fichier fermé (lecture seule) */
#define FAN_OPEN          0x00000020  /* Fichier ouvert */
#define FAN_OPEN_EXEC     0x00001000  /* Fichier ouvert pour exécution */

/* Événements de permission (BLOQUENT le processus) */
#define FAN_ACCESS_PERM   0x00020000  /* Demande de permission pour lire */
#define FAN_OPEN_PERM     0x00010000  /* Demande de permission pour ouvrir */
#define FAN_OPEN_EXEC_PERM 0x00040000 /* Demande de permission pour exécuter */

/* Événements spéciaux */
#define FAN_Q_OVERFLOW    0x00004000  /* La queue a débordé ! */
#define FAN_ONDIR         0x40000000  /* L'événement concerne un répertoire */

/* Exemple de vérification : */
if (metadata->mask & FAN_OPEN_PERM) {
    printf("Demande de permission pour ouvrir un fichier\n");
    /* VOUS DEVEZ RÉPONDRE ! */
}

if (metadata->mask & FAN_Q_OVERFLOW) {
    printf("ATTENTION: Des événements ont été perdus!\n");
    /* Déclencher un scan d'intégrité complet */
}
```

#### fd
```c
/* Le champ fd est un file descriptor OUVERT sur le fichier concerné.
 *
 * POINTS CRITIQUES :
 *
 * 1. Vous DEVEZ fermer ce fd après utilisation, sinon fuite de fd !
 *
 * 2. Ce fd a le flag FMODE_NONOTIFY : vos propres accès via ce fd
 *    NE génèrent PAS de nouveaux événements (évite les boucles infinies)
 *
 * 3. Pour obtenir le chemin du fichier :
 */

char path[PATH_MAX];
char proc_fd_path[64];

snprintf(proc_fd_path, sizeof(proc_fd_path), "/proc/self/fd/%d", metadata->fd);
ssize_t len = readlink(proc_fd_path, path, sizeof(path) - 1);
if (len > 0) {
    path[len] = '\0';
    printf("Fichier: %s\n", path);
}

/* 4. Pour lire le contenu du fichier (scan antivirus, hash, etc.) : */

char content_buf[4096];
ssize_t bytes_read = read(metadata->fd, content_buf, sizeof(content_buf));

/* 5. Cas spéciaux pour fd : */

if (metadata->fd == FAN_NOFD) {
    /* Pas de fd disponible. Cela arrive :
     * - Lors d'un FAN_Q_OVERFLOW
     * - Avec FAN_REPORT_FID (vous recevez un file handle à la place)
     */
}
```

#### pid
```c
/* Le champ pid identifie le processus ayant déclenché l'événement.
 *
 * ATTENTION aux race conditions !
 * Entre le moment où l'événement est généré et celui où vous le traitez,
 * le processus peut avoir terminé, et son PID peut avoir été réutilisé.
 */

/* Pour obtenir des informations sur le processus : */

char exe_path[PATH_MAX];
char proc_exe[64];

snprintf(proc_exe, sizeof(proc_exe), "/proc/%d/exe", metadata->pid);
ssize_t len = readlink(proc_exe, exe_path, sizeof(exe_path) - 1);
if (len > 0) {
    exe_path[len] = '\0';
    printf("Exécutable: %s\n", exe_path);
} else {
    /* Le processus n'existe peut-être plus */
    printf("Processus %d n'existe plus ou accès refusé\n", metadata->pid);
}

/* Pour éviter les race conditions (Linux 5.15+), utilisez FAN_REPORT_PIDFD
 * qui vous donne un file descriptor sur le processus au lieu d'un simple PID.
 * Ce fd reste valide même si le processus termine et que son PID est réutilisé.
 */
```

### 4.2 fanotify_response : votre réponse aux permission events

```c
struct fanotify_response {
    __s32 fd;       /* Le fd de l'événement (copié depuis metadata->fd) */
    __u32 response; /* Votre décision : FAN_ALLOW ou FAN_DENY */
};

/* Valeurs possibles pour response : */
#define FAN_ALLOW  0x01  /* Autoriser l'accès */
#define FAN_DENY   0x02  /* Refuser l'accès (errno = EPERM pour le processus) */

/* Depuis Linux 5.0, vous pouvez aussi ajouter : */
#define FAN_AUDIT  0x10  /* Demander la génération d'un log audit */
/* (requiert CAP_AUDIT_WRITE) */

/* Depuis Linux 6.13, avec FAN_CLASS_PRE_CONTENT uniquement : */
/* Vous pouvez spécifier l'erreur retournée au processus : */
#define FAN_DENY_ERRNO(e)  /* Refuse avec errno = e */
/* Valeurs autorisées : EPERM, EIO, EBUSY, ETXTBSY, EAGAIN, ENOSPC, EDQUOT */

/* Exemple d'utilisation : */
void respond_to_permission_event(int fanotify_fd, 
                                 struct fanotify_event_metadata *event,
                                 bool allow) {
    struct fanotify_response response;
    
    response.fd = event->fd;
    response.response = allow ? FAN_ALLOW : FAN_DENY;
    
    /* Optionnel : demander un log audit */
    if (!allow) {
        response.response |= FAN_AUDIT;  /* Si vous avez CAP_AUDIT_WRITE */
    }
    
    ssize_t ret = write(fanotify_fd, &response, sizeof(response));
    if (ret != sizeof(response)) {
        perror("write fanotify response");
        /* ATTENTION: Si vous ne répondez pas, le processus reste bloqué
         * jusqu'à ce que vous fermiez le fd fanotify (auquel cas tous
         * les événements en attente reçoivent FAN_ALLOW par défaut)
         */
    }
}
```

---

## 5. Le mécanisme de permission events

### 5.1 Comment le blocage fonctionne-t-il au niveau kernel ?

Quand un processus fait un appel système qui correspond à un permission event que vous surveillez :

```c
/* Côté processus demandeur (simplifié) */
int fd = open("/etc/shadow", O_RDONLY);
/* Le processus est maintenant BLOQUÉ dans le kernel... */

/* Ce qui se passe dans le kernel (pseudo-code simplifié) : */

// Dans fs/open.c, fonction do_sys_open() :
1. Vérifications standards (permissions UNIX, ACL, etc.)
2. Appel à fsnotify_open() qui vérifie les marks fanotify
3. Si un mark avec FAN_OPEN_PERM existe :
   a. Créer un fanotify_perm_event
   b. L'ajouter à la queue du groupe fanotify
   c. Mettre le processus en état TASK_INTERRUPTIBLE
   d. Attendre une réponse ou un timeout
4. Quand la réponse arrive :
   a. Si FAN_ALLOW : continuer l'open() normalement
   b. Si FAN_DENY : retourner -EPERM

/* Retour côté processus demandeur : */
if (fd == -1 && errno == EPERM) {
    printf("Accès refusé par le système de sécurité\n");
}
```

### 5.2 Le problème du deadlock et comment l'éviter

**Scénario de deadlock :**

```
┌─────────────────────────────────────────────────────────────────────┐
│ 1. Votre HIDS surveille "/" avec FAN_OPEN_PERM                      │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 2. Un processus veut ouvrir /etc/passwd                             │
│    → Événement FAN_OPEN_PERM généré                                │
│    → Le processus est bloqué                                        │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 3. Votre HIDS traite l'événement et décide de consulter             │
│    une base de règles dans /var/lib/hids/rules.db                  │
│    → Votre HIDS fait open("/var/lib/hids/rules.db")                │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│ 4. DEADLOCK !                                                        │
│    → L'open() de votre HIDS génère un FAN_OPEN_PERM                │
│    → Mais votre HIDS est occupé à traiter l'événement précédent    │
│    → Il ne peut pas lire ce nouvel événement                       │
│    → Votre HIDS et le processus original sont tous deux bloqués    │
└─────────────────────────────────────────────────────────────────────┘
```

**Solutions :**

```c
/* SOLUTION 1 : Ignorer les événements de son propre PID */
void handle_event(struct fanotify_event_metadata *event) {
    /* Vérifier si c'est nous-mêmes */
    if (event->pid == getpid()) {
        /* S'auto-autoriser immédiatement */
        respond_allow(event);
        return;
    }
    /* Traitement normal... */
}

/* SOLUTION 2 : Architecture multi-threadée */
/*
 * Thread 1 (Reader) : Lit les événements et les met dans une queue interne
 * Thread 2+ (Workers) : Traitent les événements et répondent
 *
 * Le Reader n'accède JAMAIS au filesystem pendant le traitement
 */

/* SOLUTION 3 : Marquer les fichiers de configuration comme ignorés */
fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_IGNORED_MASK,
              FAN_OPEN_PERM,
              AT_FDCWD, "/var/lib/hids/");

/* SOLUTION 4 : Charger toute la configuration en mémoire au démarrage */
/* Et ne plus jamais accéder au filesystem pour les décisions */
```

### 5.3 Timeout et comportement par défaut

```c
/* Que se passe-t-il si vous ne répondez jamais ? */

/*
 * Le processus reste bloqué indéfiniment... jusqu'à ce que :
 *
 * 1. Vous fermiez le fd fanotify
 *    → Tous les événements en attente reçoivent FAN_ALLOW automatiquement
 *
 * 2. Le processus demandeur reçoive un signal (SIGKILL, etc.)
 *    → L'appel système est interrompu avec EINTR
 *
 * 3. Le système soit redémarré
 *
 * IL N'Y A PAS DE TIMEOUT PAR DÉFAUT !
 */

/* Bonnes pratiques : */

/* 1. Toujours répondre dans un délai raisonnable */
#define MAX_RESPONSE_TIME_MS 5000  /* 5 secondes max */

/* 2. Avoir un timeout dans votre event loop */
struct pollfd pfd = { .fd = fanotify_fd, .events = POLLIN };
int timeout_ms = 1000;  /* Vérifier toutes les secondes */

while (running) {
    int ret = poll(&pfd, 1, timeout_ms);
    if (ret > 0) {
        process_events();
    }
    /* Même si timeout, vérifier si des réponses sont en retard */
    check_and_respond_stale_events();
}

/* 3. En cas de crash imminent, fermer proprement le fd */
void signal_handler(int sig) {
    close(fanotify_fd);  /* Libère tous les processus en attente */
    _exit(1);
}
signal(SIGTERM, signal_handler);
signal(SIGINT, signal_handler);
```

---

## Résumé des points clés de cette partie

1. **fanotify vs inotify** : fanotify peut BLOQUER les accès (permission events), inotify ne peut que notifier après coup

2. **Classes** : Utilisez `FAN_CLASS_CONTENT` pour un HIDS — vous voyez les fichiers dans leur état final et pouvez bloquer les accès

3. **Marks** : Combinez `FAN_MARK_MOUNT` pour la couverture globale et `FAN_MARK_INODE` pour les fichiers critiques

4. **Permission events** : VOUS DEVEZ TOUJOURS RÉPONDRE, sinon le processus demandeur reste bloqué

5. **Deadlocks** : Évitez d'accéder au filesystem surveillé depuis le thread qui traite les événements

---

## Références

- man fanotify(7) : https://man7.org/linux/man-pages/man7/fanotify.7.html
- man fanotify_init(2) : https://man7.org/linux/man-pages/man2/fanotify_init.2.html
- man fanotify_mark(2) : https://man7.org/linux/man-pages/man2/fanotify_mark.2.html
- LWN.net - The fanotify API : https://lwn.net/Articles/339399/
- Kernel source : fs/notify/fanotify/
