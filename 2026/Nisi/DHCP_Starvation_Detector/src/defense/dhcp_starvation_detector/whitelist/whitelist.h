#ifndef WHITELIST_H
#define WHITELIST_H

#include <stdint.h>

#define MAC_LEN        6
#define WHITELIST_MAX  256

typedef struct {
  uint8_t  macs[WHITELIST_MAX][MAC_LEN]; /* sorted array of MAC addresses */
  int      count;
  char     filepath[256];               /* path to backing file on disk */
} whitelist_t;

/* Return the whitelist file path from config (paths.whitelist), resolving
 * relative paths against the detector project root. */
const char *whitelist_cfg_path(void);

/* Load MACs from file into wl. Creates an empty whitelist if file does not
 * exist. Returns 0 on success, -1 on error. */
int whitelist_load(whitelist_t *wl, const char *path);

/* Return 1 if mac is in the whitelist, 0 otherwise. */
int whitelist_contains(const whitelist_t *wl, const uint8_t mac[MAC_LEN]);

/* Add mac to the in-memory whitelist (sorted) and append it to the backing
 * file with label as an inline comment.
 * Returns  0 on success,
 *          1 if mac is already present (no-op),
 *         -1 on error. */
int whitelist_add(whitelist_t *wl,
                  const uint8_t mac[MAC_LEN],
                  const char *label);

/* Remove mac from the in-memory whitelist and from the backing file.
 * Returns  0 on success,
 *          1 if mac was not present (no-op),
 *         -1 on error. */
int whitelist_remove(whitelist_t *wl, const uint8_t mac[MAC_LEN]);

#endif /* WHITELIST_H */
