#ifndef ALLOWDENY_WATCHER_H
#define ALLOWDENY_WATCHER_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Start background watcher thread that monitors the --allow/--deny host files.
 *
 * allow_path: Path to the file supplied to --allowfile, or NULL if none.
 * deny_path : Path to the file supplied to --denyfile,  or NULL if none.
 *
 * Returns 0 on success, -1 on failure.
 */
int start_allowdeny_watcher(const char *allow_path, const char *deny_path);

#ifdef __cplusplus
}
#endif

#ifndef WIN32
#include <pthread.h>

/* Global mutex guarding access to o.allowset / o.denyset */
extern pthread_mutex_t g_allowdeny_mutex;
#endif

#endif /* ALLOWDENY_WATCHER_H */