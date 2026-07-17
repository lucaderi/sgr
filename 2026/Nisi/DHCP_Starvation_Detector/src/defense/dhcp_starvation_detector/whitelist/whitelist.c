#include "whitelist.h"
#include "../config/defense_config.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>
#include <sys/stat.h>
#include <unistd.h>

const char *whitelist_cfg_path(void)
{
    static char path[512];
    const char *resolved = cfg_resolve_path("paths.whitelist",
                                            "db/whitelist.txt");
    int n;

    if (!resolved)
        resolved = "";
    n = snprintf(path, sizeof(path), "%s", resolved);
    if (n < 0 || (size_t)n >= sizeof(path)) {
        fprintf(stderr,
                "[WARN] whitelist_cfg_path: resolved path truncated; "
                "using db/whitelist.txt fallback\n");
        snprintf(path, sizeof(path), "%s", "db/whitelist.txt");
    }
    return path;
}

/* ---- helpers ---------------------------------------------------------- */

/* Parse "aa:bb:cc:dd:ee:ff" into mac[6]. Returns 0 on success, -1 on error. */
static int parse_mac(const char *str, uint8_t mac[MAC_LEN])
{
  unsigned int b[MAC_LEN];
  if (sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
             &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != MAC_LEN)
    return -1;
  for (int i = 0; i < MAC_LEN; i++) {
    if (b[i] > 0xff)
      return -1;
    mac[i] = (uint8_t)b[i];
  }
  return 0;
}

/* Binary search: return index of mac if found, -1 if not found.
 * Also sets *insert_pos to the index where mac should be inserted. */
static int find(const whitelist_t *wl,
                const uint8_t mac[MAC_LEN],
                int *insert_pos)
{
  int lo = 0, hi = wl->count - 1;

  while (lo <= hi) {
    int mid = (lo + hi) / 2;
    int cmp = memcmp(mac, wl->macs[mid], MAC_LEN);
    if (cmp == 0) {
      if (insert_pos) *insert_pos = mid;
      return mid;
    }
    if (cmp < 0) hi = mid - 1;
    else         lo = mid + 1;
  }

  if (insert_pos) *insert_pos = lo;
  return -1;
}

/* ---- whitelist_load --------------------------------------------------- */
int whitelist_load(whitelist_t *wl, const char *path)
{
  FILE *fp;
  char  line[128];
  uint8_t mac[MAC_LEN];
  int line_no = 0;

  if (!wl || !path || !*path) {
    fprintf(stderr, "[FAIL] whitelist_load: invalid arguments\n");
    return -1;
  }

  memset(wl, 0, sizeof(*wl));
  if (snprintf(wl->filepath, sizeof(wl->filepath), "%s", path) < 0 ||
      strlen(path) >= sizeof(wl->filepath)) {
    fprintf(stderr, "[FAIL] whitelist_load: path too long: %s\n", path);
    return -1;
  }

  fp = fopen(path, "r");
  if (fp == NULL) {
    if (errno == ENOENT) {
      /* create parent directory if needed */
      char tmp[256];
      if (snprintf(tmp, sizeof(tmp), "%s", path) < 0 ||
          strlen(path) >= sizeof(tmp)) {
        fprintf(stderr, "[FAIL] whitelist_load: path too long: %s\n", path);
        return -1;
      }
      if (mkdir(dirname(tmp), 0755) != 0 && errno != EEXIST) {
        fprintf(stderr,
                "[WARN] whitelist_load: could not create parent directory "
                "for %s: %s\n",
                path, strerror(errno));
      }

      fp = fopen(path, "w");
      if (fp == NULL) {
        fprintf(stderr, "[FAIL] whitelist_load: fopen create %s: %s\n",
                path, strerror(errno));
        return -1;
      }
      if (fclose(fp) != 0) {
        fprintf(stderr, "[FAIL] whitelist_load: fclose create %s: %s\n",
                path, strerror(errno));
        return -1;
      }
      return 0;
    }
    fprintf(stderr, "[FAIL] whitelist_load: fopen %s: %s\n",
            path, strerror(errno));
    return -1;
  }

  while (fgets(line, sizeof(line), fp) != NULL) {
    char *p = line;
    line_no++;

    /* skip leading whitespace */
    while (*p == ' ' || *p == '\t') p++;

    /* skip empty lines and full-line comments */
    if (*p == '#' || *p == '\n' || *p == '\0')
      continue;

    if (parse_mac(p, mac) != 0) {
      fprintf(stderr,
              "[WARN] whitelist_load: ignoring malformed line %d in %s\n",
              line_no, path);
      continue;
    }

    if (wl->count >= WHITELIST_MAX) {
      fprintf(stderr, "[WARN] whitelist_load: max capacity (%d) reached, "
              "remaining entries ignored\n", WHITELIST_MAX);
      break;
    }

    /* Insert maintaining sorted order */
    int pos;
    if (find(wl, mac, &pos) >= 0)
      continue; /* duplicate — skip */

    memmove(wl->macs[pos + 1], wl->macs[pos],
            (wl->count - pos) * MAC_LEN);
    memcpy(wl->macs[pos], mac, MAC_LEN);
    wl->count++;
  }

  if (ferror(fp)) {
    fprintf(stderr, "[FAIL] whitelist_load: read error on %s\n", path);
    fclose(fp);
    return -1;
  }

  if (fclose(fp) != 0) {
    fprintf(stderr, "[FAIL] whitelist_load: fclose %s: %s\n",
            path, strerror(errno));
    return -1;
  }
  return 0;
}

/* ---- whitelist_contains ----------------------------------------------- */
int whitelist_contains(const whitelist_t *wl, const uint8_t mac[MAC_LEN])
{
  return find(wl, mac, NULL) >= 0;
}

/* ---- whitelist_add ---------------------------------------------------- */
int whitelist_add(whitelist_t *wl,
                  const uint8_t mac[MAC_LEN],
                  const char *label)
{
  FILE *fp;
  int   pos;

  if (!wl || !mac || wl->filepath[0] == '\0') {
    fprintf(stderr, "[FAIL] whitelist_add: invalid arguments\n");
    return -1;
  }

  if (find(wl, mac, &pos) >= 0)
    return 1; /* already present */

  if (wl->count >= WHITELIST_MAX) {
    fprintf(stderr, "[FAIL] whitelist_add: max capacity (%d) reached\n",
            WHITELIST_MAX);
    return -1;
  }

  /* Append to file first; update memory only if persistence succeeds. */
  fp = fopen(wl->filepath, "a");
  if (fp == NULL) {
    fprintf(stderr, "[FAIL] whitelist_add: fopen %s: %s\n",
            wl->filepath, strerror(errno));
    return -1;
  }

  if (fprintf(fp, "%02x:%02x:%02x:%02x:%02x:%02x   # %s\n",
              mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
              label ? label : "") < 0) {
    fprintf(stderr, "[FAIL] whitelist_add: write %s: %s\n",
            wl->filepath, strerror(errno));
    fclose(fp);
    return -1;
  }

  if (fclose(fp) != 0) {
    fprintf(stderr, "[FAIL] whitelist_add: fclose %s: %s\n",
            wl->filepath, strerror(errno));
    return -1;
  }

  /* Insert into sorted array */
  memmove(wl->macs[pos + 1], wl->macs[pos],
          (wl->count - pos) * MAC_LEN);
  memcpy(wl->macs[pos], mac, MAC_LEN);
  wl->count++;
  return 0;
}

/* ---- whitelist_remove ------------------------------------------------- */
int whitelist_remove(whitelist_t *wl, const uint8_t mac[MAC_LEN])
{
  int pos;
  char tmp_path[sizeof(wl->filepath) + 8];
  FILE *in;
  FILE *out;
  char line[256];
  int removed_from_file = 0;

  if (!wl || !mac || wl->filepath[0] == '\0') {
    fprintf(stderr, "[FAIL] whitelist_remove: invalid arguments\n");
    return -1;
  }

  if (find(wl, mac, &pos) < 0)
    return 1; /* not present */

  if (snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", wl->filepath) >=
      (int)sizeof(tmp_path)) {
    fprintf(stderr, "[FAIL] whitelist_remove: path too long\n");
    return -1;
  }

  in = fopen(wl->filepath, "r");
  if (!in) {
    fprintf(stderr, "[FAIL] whitelist_remove: fopen input %s: %s\n",
            wl->filepath, strerror(errno));
    return -1;
  }

  out = fopen(tmp_path, "w");
  if (!out) {
    fprintf(stderr, "[FAIL] whitelist_remove: fopen tmp %s: %s\n",
            tmp_path, strerror(errno));
    fclose(in);
    return -1;
  }

  while (fgets(line, sizeof(line), in)) {
    char *p = line;
    uint8_t parsed[MAC_LEN];

    while (*p == ' ' || *p == '\t') p++;

    if (*p != '#' && *p != '\n' && *p != '\0' &&
        parse_mac(p, parsed) == 0 &&
        memcmp(parsed, mac, MAC_LEN) == 0) {
      removed_from_file = 1;
      continue;
    }

    if (fputs(line, out) == EOF) {
      fprintf(stderr, "[FAIL] whitelist_remove: write tmp %s: %s\n",
              tmp_path, strerror(errno));
      fclose(in);
      fclose(out);
      unlink(tmp_path);
      return -1;
    }
  }

  if (ferror(in) || ferror(out)) {
    fprintf(stderr, "[FAIL] whitelist_remove: file error while rewriting %s\n",
            wl->filepath);
    fclose(in);
    fclose(out);
    unlink(tmp_path);
    return -1;
  }

  if (fclose(in) != 0) {
    fprintf(stderr, "[FAIL] whitelist_remove: fclose input %s: %s\n",
            wl->filepath, strerror(errno));
    fclose(out);
    unlink(tmp_path);
    return -1;
  }
  if (fclose(out) != 0) {
    fprintf(stderr, "[FAIL] whitelist_remove: fclose tmp %s: %s\n",
            tmp_path, strerror(errno));
    unlink(tmp_path);
    return -1;
  }

  if (rename(tmp_path, wl->filepath) != 0) {
    fprintf(stderr, "[FAIL] whitelist_remove: rename %s -> %s: %s\n",
            tmp_path, wl->filepath, strerror(errno));
    unlink(tmp_path);
    return -1;
  }

  memmove(wl->macs[pos], wl->macs[pos + 1],
          (wl->count - pos - 1) * MAC_LEN);
  wl->count--;

  if (!removed_from_file) {
    fprintf(stderr,
            "[WARN] whitelist_remove: MAC was present in memory but not in %s\n",
            wl->filepath);
  }

  return 0;
}
