#include "allowdeny_watcher.h"
#include "ncat_core.h"
#include "util.h"

#ifdef WIN32
/* Windows headers */
#include <windows.h>
#else  /* POSIX */
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#endif

/* ------------------------------------------------------------------------- */
/* Internal helpers                                                          */
/* ------------------------------------------------------------------------- */

struct watcher_paths {
    char *allow_path;
    char *deny_path;
};

#ifndef WIN32
static void *watcher_thread(void *arg)
{
    struct watcher_paths *wp = (struct watcher_paths *)arg;

    /* TODO: Add inotify/kqueue implementation in later steps. */
    (void)wp; /* suppress unused warning for now */

    /* Thread exits immediately in this skeleton. */
    return NULL;
}
#endif

/* ------------------------------------------------------------------------- */
/* Public API                                                                */
/* ------------------------------------------------------------------------- */

int start_allowdeny_watcher(const char *allow_path, const char *deny_path)
{
    /* If the feature is not requested, simply do nothing. Caller will ensure
       not to call us when flag is absent, but be tolerant. */
    if (allow_path == NULL && deny_path == NULL)
        return 0;

#ifndef WIN32
    pthread_t tid;
    struct watcher_paths *wp = (struct watcher_paths *)safe_malloc(sizeof(*wp));
    wp->allow_path = allow_path ? Strdup(allow_path) : NULL;
    wp->deny_path  = deny_path  ? Strdup(deny_path)  : NULL;

    if (pthread_create(&tid, NULL, watcher_thread, wp) != 0) {
        bye("Failed to create allow/deny watcher thread: %s", strerror(errno));
        return -1; /* not reached */
    }
    pthread_detach(tid);
#else
    /* TODO: Windows ReadDirectoryChangesW implementation in later steps. */
    (void)allow_path;
    (void)deny_path;
#endif

    return 0;
}