#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../config/defense_config.h"
#include "whitelist.h"

static int load_test_config(const char *path)
{
  const char *env_path;

  if (path && *path)
    return cfg_load(path);

  env_path = getenv(DEFENSE_CONFIG_ENV);
  if (env_path && *env_path)
    return cfg_load(env_path);

  if (access(DEFENSE_CONFIG_DEFAULT_PATH, R_OK) == 0)
    return cfg_load(DEFENSE_CONFIG_DEFAULT_PATH);
  if (access(DEFENSE_CONFIG_PROJECT_PATH, R_OK) == 0)
    return cfg_load(DEFENSE_CONFIG_PROJECT_PATH);
  if (access("../" DEFENSE_CONFIG_PROJECT_PATH, R_OK) == 0)
    return cfg_load("../" DEFENSE_CONFIG_PROJECT_PATH);

  fprintf(stderr,
          "[WARN] [test_whitelist] config file not found; using compiled "
          "defaults and a local scratch whitelist fallback.\n");
  cfg_use_defaults(".");
  return 0;
}

static void usage(const char *prog)
{
  fprintf(stderr,
      "usage: %s [--config FILE] [--file WHITELIST_FILE]\n"
      "       %s [--config FILE] [WHITELIST_FILE]\n"
      "\n"
      "  Standalone test for the whitelist module.\n"
      "  It uses a clean scratch whitelist file, then verifies load, add,\n"
      "  duplicate handling, lookup, remove, reload, and backing-file updates.\n"
      "\n"
      "options:\n"
      "  --config FILE      optional YAML config path; if omitted, the test uses\n"
      "                     DHCP_DEFENSE_CONFIG, config/config.yaml, the project\n"
      "                     default config path, or compiled defaults as fallback\n"
      "  --file FILE        explicit whitelist test file. Warning: the file is\n"
      "                     overwritten during the test\n"
      "\n"
      "default behavior:\n"
      "  Without --file, the test uses paths.whitelist from config and appends\n"
      "  .test, so the real whitelist DB is not modified.\n"
      "\n"
      "examples:\n"
      "  %s\n"
      "  %s --config src/defense/dhcp_starvation_detector/config/config.yaml\n"
      "  %s --file /tmp/test_whitelist.txt\n",
      prog, prog, prog, prog, prog);
}

static void print_whitelist(const whitelist_t *wl)
{
  printf("  count=%d\n", wl->count);
  for (int i = 0; i < wl->count; i++) {
    const uint8_t *m = wl->macs[i];
    printf("  [%d] %02x:%02x:%02x:%02x:%02x:%02x\n",
           i, m[0], m[1], m[2], m[3], m[4], m[5]);
  }
}

static int check_int(const char *label, int got, int expected)
{
  if (got == expected)
    return 0;

  printf("[FAIL] [test_whitelist] %s: got=%d expected=%d\n",
         label, got, expected);
  return 1;
}

int main(int argc, char *argv[])
{
  static char scratch_path[1024];
  const char *config_path = NULL;
  const char *explicit_path = NULL;
  const char *path;
  whitelist_t wl;
  int ret;
  int cleanup_path = 0;
  int failures = 0;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-h") == 0 ||
        strcmp(argv[i], "--help") == 0) {
      usage(argv[0]);
      return 0;
    }
    if (strcmp(argv[i], "--config") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "[FAIL] [test_whitelist] --config requires a value\n");
        usage(argv[0]);
        return 1;
      }
      config_path = argv[i];
      continue;
    }
    if (strcmp(argv[i], "--file") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "[FAIL] [test_whitelist] --file requires a value\n");
        usage(argv[0]);
        return 1;
      }
      explicit_path = argv[i];
      continue;
    }
    if (argv[i][0] == '-') {
      fprintf(stderr, "[FAIL] [test_whitelist] unknown argument: %s\n", argv[i]);
      usage(argv[0]);
      return 1;
    }
    if (explicit_path) {
      fprintf(stderr, "[FAIL] [test_whitelist] too many whitelist file paths\n");
      usage(argv[0]);
      return 1;
    }
    explicit_path = argv[i];
  }

  if (load_test_config(config_path) != 0)
    return 1;

  if (explicit_path) {
    path = explicit_path;
    printf("[WARN] explicit whitelist test file provided; this test overwrites it: %s\n",
           path);
  } else {
    const char *base = strcmp(cfg_loaded_path(), "<compiled-defaults>") == 0
                       ? "test_whitelist.txt"
                       : whitelist_cfg_path();
    int n = snprintf(scratch_path, sizeof(scratch_path), "%s.test", base);
    if (n < 0 || (size_t)n >= sizeof(scratch_path)) {
      fprintf(stderr, "[FAIL] [test_whitelist] scratch whitelist path is too long\n");
      return 1;
    }
    path = scratch_path;
    printf("[WARN] using scratch whitelist file; real whitelist is not modified: %s\n",
           path);
    cleanup_path = 1;
  }

  (void)unlink(path);
  printf("using clean test whitelist file: %s\n\n", path);

  /* --- load (creates file if absent) ------------------------------------ */
  ret = whitelist_load(&wl, path);
  printf("load clean file: ret=%d  count=%d  (expect 0, 0)\n", ret, wl.count);
  failures += check_int("load clean file ret", ret, 0);
  failures += check_int("load clean file count", wl.count, 0);

  /* --- add entries ------------------------------------------------------- */
  uint8_t mac_router[]  = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  uint8_t mac_printer[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
  uint8_t mac_server[]  = {0x55, 0x66, 0x77, 0x88, 0x99, 0x00};

  failures += check_int("add router", whitelist_add(&wl, mac_router, "router"), 0);
  failures += check_int("add printer", whitelist_add(&wl, mac_printer, "printer"), 0);
  failures += check_int("add server", whitelist_add(&wl, mac_server, "server"), 0);

  printf("\nafter 3 adds:\n");
  print_whitelist(&wl);
  failures += check_int("count after add", wl.count, 3);

  /* --- duplicate add ----------------------------------------------------- */
  ret = whitelist_add(&wl, mac_router, "router-duplicate");
  printf("\nadd duplicate: ret=%d  (expect 1)\n", ret);
  printf("count after duplicate add=%d  (expect 3)\n", wl.count);
  failures += check_int("duplicate add ret", ret, 1);
  failures += check_int("count after duplicate", wl.count, 3);

  /* --- lookup ------------------------------------------------------------ */
  uint8_t mac_unknown[] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x01};
  printf("\ncontains router:  %d  (expect 1)\n",
         whitelist_contains(&wl, mac_router));
  printf("contains unknown: %d  (expect 0)\n",
         whitelist_contains(&wl, mac_unknown));
  failures += check_int("contains router", whitelist_contains(&wl, mac_router), 1);
  failures += check_int("contains unknown", whitelist_contains(&wl, mac_unknown), 0);

  /* --- reload from file and verify order --------------------------------- */
  whitelist_t wl2;
  ret = whitelist_load(&wl2, path);
  printf("\nreloaded from file:\n");
  print_whitelist(&wl2);
  failures += check_int("reload ret", ret, 0);
  failures += check_int("reload count", wl2.count, 3);
  failures += check_int("reload contains router", whitelist_contains(&wl2, mac_router), 1);
  failures += check_int("reload contains printer", whitelist_contains(&wl2, mac_printer), 1);
  failures += check_int("reload contains server", whitelist_contains(&wl2, mac_server), 1);

  /* --- remove entries ---------------------------------------------------- */
  ret = whitelist_remove(&wl2, mac_printer);
  printf("\nremove printer: ret=%d  (expect 0)\n", ret);
  printf("contains printer after remove: %d  (expect 0)\n",
         whitelist_contains(&wl2, mac_printer));
  failures += check_int("remove printer ret", ret, 0);
  failures += check_int("count after remove", wl2.count, 2);
  failures += check_int("contains printer after remove",
                        whitelist_contains(&wl2, mac_printer), 0);

  ret = whitelist_remove(&wl2, mac_unknown);
  printf("remove unknown: ret=%d  (expect 1)\n", ret);
  failures += check_int("remove unknown ret", ret, 1);

  printf("\nfile contents:\n");
  FILE *fp = fopen(path, "r");
  if (fp) {
    char line[128];
    while (fgets(line, sizeof(line), fp))
      printf("  %s", line);
    fclose(fp);
  }

  if (cleanup_path)
    (void)unlink(path);

  if (failures > 0) {
    printf("\n[FAIL] [test_whitelist] %d check(s) failed\n", failures);
    return 1;
  }

  printf("\n[test_whitelist] all checks passed\n");
  return 0;
}
