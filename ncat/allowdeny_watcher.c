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
#include <sys/inotify.h>
#include <sys/stat.h>
#include <time.h>
#endif

/* ------------------------------------------------------------------------- */
/* Internal helpers                                                          */
/* ------------------------------------------------------------------------- */

struct watcher_paths {
    char *allow_path;
    char *deny_path;
};

#ifndef WIN32
pthread_mutex_t g_allowdeny_mutex = PTHREAD_MUTEX_INITIALIZER;

static void reload_rules(const struct watcher_paths *wp)
{
    /* Build new addrsets */
    struct addrset *new_allow = NULL;
    struct addrset *new_deny  = NULL;

    if (wp->allow_path) {
        FILE *fd = fopen(wp->allow_path, "r");
        if (fd) {
            new_allow = addrset_new();
            if (!addrset_add_file(new_allow, fd, o.af, !o.nodns)) {
                loguser("[WARN] Error parsing allow file %s, keeping old set.\n", wp->allow_path);
                addrset_free(new_allow);
                new_allow = NULL;
            }
            fclose(fd);
        }
    }

    if (wp->deny_path) {
        FILE *fd = fopen(wp->deny_path, "r");
        if (fd) {
            new_deny = addrset_new();
            if (!addrset_add_file(new_deny, fd, o.af, !o.nodns)) {
                loguser("[WARN] Error parsing deny file %s, keeping old set.\n", wp->deny_path);
                addrset_free(new_deny);
                new_deny = NULL;
            }
            fclose(fd);
        }
    }

    /* Swap in atomically under mutex */
    pthread_mutex_lock(&g_allowdeny_mutex);
    if (new_allow) {
        addrset_free(o.allowset);
        o.allowset = new_allow;
    }
    if (new_deny) {
        addrset_free(o.denyset);
        o.denyset = new_deny;
    }
    pthread_mutex_unlock(&g_allowdeny_mutex);

    /* Log reload time */
    time_t now = time(NULL);
    char tsbuf[32];
    struct tm tmval;
    localtime_r(&now, &tmval);
    strftime(tsbuf, sizeof(tsbuf), "%Y-%m-%d %H:%M:%S", &tmval);

    loguser("[INFO] Re-loaded allow/deny rules (modified at %s)\n", tsbuf);
}

static void *watcher_thread(void *arg)
{
    struct watcher_paths *wp = (struct watcher_paths *)arg;

    int infd = inotify_init1(IN_NONBLOCK);
    if (infd < 0) {
        loguser("[WARN] Failed to init inotify: %s\n", strerror(errno));
        free(wp);
        return NULL;
    }

    int wd_allow = -1, wd_deny = -1;
    if (wp->allow_path)
        wd_allow = inotify_add_watch(infd, wp->allow_path, IN_MODIFY | IN_CLOSE_WRITE | IN_MOVE_SELF | IN_DELETE_SELF);
    if (wp->deny_path)
        wd_deny = inotify_add_watch(infd, wp->deny_path, IN_MODIFY | IN_CLOSE_WRITE | IN_MOVE_SELF | IN_DELETE_SELF);

    if (wd_allow < 0 && wp->allow_path)
        loguser("[WARN] Cannot watch %s: %s\n", wp->allow_path, strerror(errno));
    if (wd_deny < 0 && wp->deny_path)
        loguser("[WARN] Cannot watch %s: %s\n", wp->deny_path, strerror(errno));

    /* Main loop */
    const size_t bufsize = 4096;
    char *buf = (char *)safe_malloc(bufsize);

    while (1) {
        ssize_t len = read(infd, buf, bufsize);
        if (len <= 0) {
            if (errno == EAGAIN || errno == EINTR) {
                /* Sleep briefly to avoid busy loop */
                usleep(200 * 1000);
                continue;
            }
            else {
                break;
            }
        }

        for (char *p = buf; p < buf + len;) {
            struct inotify_event *ev = (struct inotify_event *)p;
            if ((ev->mask & (IN_MODIFY | IN_CLOSE_WRITE | IN_MOVE_SELF | IN_DELETE_SELF))) {
                reload_rules(wp);
            }

            p += sizeof(struct inotify_event) + ev->len;
        }
    }

    free(buf);
    close(infd);
    free(wp);
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