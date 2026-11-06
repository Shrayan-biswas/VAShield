/*
 * VAShield launch-page generator
 * -------------------------------
 * Interactively asks about the scan target and writes a ready-to-open
 * HTML page (based on frontend/template.html) with those answers
 * pre-filled, so you don't have to hand-edit index.html or its <script>
 * block before every scan.
 *
 * This program does NOT talk to the network itself and does NOT bypass
 * the backend's ownership check in any way -- it only fills in a form.
 * The backend (ownership.py) still independently verifies ownership of
 * any non-local target before a scan is allowed to start.
 *
 * Build:
 *   cc -O2 -o configure configure.c
 *
 * Run (from the vashield/tools directory, or anywhere -- it will look
 * for frontend/template.html relative to itself and a few common spots):
 *   ./configure
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LINE_MAX_LEN 1024

/* ---------- small string helpers ---------- */

static void trim_newline(char *s) {
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) {
        s[--n] = '\0';
    }
}

/* Reads a line of input, trims it, and returns a heap copy.
 * If the user just hits enter, returns a heap copy of `def` instead. */
static char *ask(const char *prompt, const char *def) {
    char buf[LINE_MAX_LEN];
    if (def && def[0] != '\0')
        printf("%s [%s]: ", prompt, def);
    else
        printf("%s: ", prompt);
    fflush(stdout);

    if (!fgets(buf, sizeof(buf), stdin)) {
        buf[0] = '\0';
    }
    trim_newline(buf);

    const char *chosen = (buf[0] != '\0') ? buf : (def ? def : "");
    char *out = malloc(strlen(chosen) + 1);
    if (!out) { fprintf(stderr, "out of memory\n"); exit(1); }
    strcpy(out, chosen);
    return out;
}

/* Yes/no prompt. Returns 1 for yes, 0 for no. */
static int ask_yn(const char *prompt, int default_yes) {
    char buf[LINE_MAX_LEN];
    printf("%s [%s]: ", prompt, default_yes ? "Y/n" : "y/N");
    fflush(stdout);
    if (!fgets(buf, sizeof(buf), stdin)) return default_yes;
    trim_newline(buf);
    if (buf[0] == '\0') return default_yes;
    return (buf[0] == 'y' || buf[0] == 'Y');
}

/* Menu prompt: prints numbered options, returns the chosen option's
 * `value` string (heap-allocated copy). */
static char *ask_menu(const char *title, const char *const labels[],
                       const char *const values[], int count, int default_idx) {
    printf("%s\n", title);
    for (int i = 0; i < count; i++) {
        printf("  %d) %s%s\n", i + 1, labels[i], (i == default_idx) ? "  (default)" : "");
    }
    char buf[LINE_MAX_LEN];
    printf("Choose [1-%d]: ", count);
    fflush(stdout);
    if (!fgets(buf, sizeof(buf), stdin)) return strdup(values[default_idx]);
    trim_newline(buf);
    if (buf[0] == '\0') return strdup(values[default_idx]);
    int choice = atoi(buf);
    if (choice < 1 || choice > count) choice = default_idx + 1;
    char *out = malloc(strlen(values[choice - 1]) + 1);
    strcpy(out, values[choice - 1]);
    return out;
}

/* Very naive local/private-host check, just to steer the interview
 * (the real, authoritative check happens server-side in ownership.py). */
static int looks_local(const char *url) {
    return strstr(url, "127.0.0.1") || strstr(url, "localhost") ||
           strstr(url, "::1") || strstr(url, "10.") ||
           strstr(url, "192.168.") || strstr(url, "172.16.");
}

/* HTML-attribute-safe escaping: this is the only place user input gets
 * embedded into the generated file, and it always lands inside a
 * value="..." attribute, so escaping & < > " ' is sufficient. */
static char *html_escape(const char *in) {
    size_t cap = strlen(in) * 6 + 1;
    char *out = malloc(cap);
    if (!out) { fprintf(stderr, "out of memory\n"); exit(1); }
    char *p = out;
    for (const unsigned char *c = (const unsigned char *)in; *c; c++) {
        switch (*c) {
            case '&': p += sprintf(p, "&amp;");  break;
            case '<': p += sprintf(p, "&lt;");   break;
            case '>': p += sprintf(p, "&gt;");   break;
            case '"': p += sprintf(p, "&quot;"); break;
            case '\'': p += sprintf(p, "&#39;"); break;
            default: *p++ = (char)*c; break;
        }
    }
    *p = '\0';
    return out;
}

/* Reads an entire file into a heap buffer (NUL-terminated). Returns
 * NULL if it can't be opened. */
static char *read_file(const char *path, long *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)len + 1);
    if (!buf) { fclose(f); fprintf(stderr, "out of memory\n"); exit(1); }
    size_t read = fread(buf, 1, (size_t)len, f);
    buf[read] = '\0';
    fclose(f);
    if (out_len) *out_len = (long)read;
    return buf;
}

/* Replaces every occurrence of `needle` in `haystack` with `repl`,
 * returning a freshly malloc'd string. Frees neither input. */
static char *replace_all(const char *haystack, const char *needle, const char *repl) {
    size_t needle_len = strlen(needle);
    size_t repl_len = strlen(repl);
    size_t count = 0;
    for (const char *p = haystack; (p = strstr(p, needle)) != NULL; p += needle_len) count++;

    size_t out_len = strlen(haystack) + count * (repl_len > needle_len ? (repl_len - needle_len) : 0);
    char *out = malloc(out_len + 1);
    if (!out) { fprintf(stderr, "out of memory\n"); exit(1); }

    char *dst = out;
    const char *src = haystack;
    const char *hit;
    while ((hit = strstr(src, needle)) != NULL) {
        size_t chunk = (size_t)(hit - src);
        memcpy(dst, src, chunk);
        dst += chunk;
        memcpy(dst, repl, repl_len);
        dst += repl_len;
        src = hit + needle_len;
    }
    strcpy(dst, src);
    return out;
}

/* apply replace_all in place (frees the old buffer, returns the new one) */
static char *apply(char *buf, const char *placeholder, const char *raw_value) {
    char *escaped = html_escape(raw_value);
    char *next = replace_all(buf, placeholder, escaped);
    free(escaped);
    free(buf);
    return next;
}

int main(int argc, char **argv) {
    printf("=== VAShield launch-page generator ===\n");
    printf("Answers below only pre-fill a form in the generated HTML page.\n");
    printf("The backend still independently verifies ownership of any\n");
    printf("non-local target before a scan is allowed to start.\n\n");

    char *api_base   = ask("Backend API base URL", "http://127.0.0.1:8000");
    char *target_url = ask("Target base URL to scan", "http://127.0.0.1:5055");

    int local = looks_local(target_url);
    if (!local) {
        printf("\nThis looks like a non-local target. Before the backend will scan it,\n"
               "you'll need to request a token from:\n"
               "  POST %s/api/v1/ownership/request-token?target_url=%s\n"
               "and publish it at:\n"
               "  GET %s/.well-known/security-check.txt\n"
               "(the generated page also has a \"Request verification token\" button\n"
               "that does this same call for you.)\n\n", api_base, target_url, target_url);
    }

    char *ports = ask("Ports to check", local ? "5055" : "443,80");

    const char *profile_labels[] = {
        "baseline_staging   -- standard, non-destructive",
        "baseline_production -- conservative, production-safe",
        "full_authenticated -- includes auth/session probes",
        "custom              -- label only"
    };
    const char *profile_values[] = {
        "baseline_staging", "baseline_production", "full_authenticated", "custom"
    };
    char *profile = ask_menu("\nScan profile:", profile_labels, profile_values, 4, 0);

    int intrusive = 0;
    if (!local) {
        printf("\nIntrusive tests (e.g. JWT alg:none bypass) actively probe auth.\n");
        intrusive = ask_yn("Enable intrusive tests? Only say yes if you're explicitly authorized", 0);
    } else {
        intrusive = ask_yn("\nEnable intrusive tests?", 0);
    }

    char *jwt_token = ask("\nJWT to analyze (optional, blank to skip)", "");

    char *inj_url = "", *inj_param = "";
    if (ask_yn("Configure an injection test target?", 0)) {
        inj_url = ask("  Injection test URL", "");
        inj_param = ask("  Injection test param", "");
    }

    char *bola_tpl = "", *tenant_a = "", *tenant_b = "", *admin_url = "", *low_priv = "";
    if (ask_yn("Configure an access-control (BOLA/BFLA) test?", 0)) {
        bola_tpl  = ask("  BOLA resource template (e.g. .../customers/{id})", "");
        tenant_a  = ask("  Tenant A token", "");
        tenant_b  = ask("  Tenant B object id", "");
        admin_url = ask("  BFLA admin-only URL", "");
        low_priv  = ask("  BFLA low-priv token", "");
    }

    char *out_path = ask("\nOutput file name", "vashield_run.html");

    /* Find template.html relative to a few likely locations. */
    const char *candidates[] = {
        "../frontend/template.html",
        "frontend/template.html",
        "./template.html",
        "vashield/frontend/template.html",
    };
    char *template_buf = NULL;
    const char *found_at = NULL;
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        template_buf = read_file(candidates[i], NULL);
        if (template_buf) { found_at = candidates[i]; break; }
    }
    if (!template_buf) {
        fprintf(stderr, "\nCould not find frontend/template.html (tried the usual relative paths).\n"
                        "Run this from the vashield/tools directory, or pass the template path\n"
                        "as an argument: %s <path-to-template.html>\n", argv[0]);
        if (argc > 1) {
            template_buf = read_file(argv[1], NULL);
            found_at = argv[1];
        }
        if (!template_buf) return 1;
    }

    template_buf = apply(template_buf, "{{API}}", api_base);
    template_buf = apply(template_buf, "{{TARGET_URL}}", target_url);
    template_buf = apply(template_buf, "{{PORTS}}", ports);
    template_buf = apply(template_buf, "{{PROFILE}}", profile);
    template_buf = apply(template_buf, "{{JWT}}", jwt_token);
    template_buf = apply(template_buf, "{{INJ_URL}}", inj_url);
    template_buf = apply(template_buf, "{{INJ_PARAM}}", inj_param);
    template_buf = apply(template_buf, "{{BOLA_TPL}}", bola_tpl);
    template_buf = apply(template_buf, "{{TENANT_A}}", tenant_a);
    template_buf = apply(template_buf, "{{TENANT_B}}", tenant_b);
    template_buf = apply(template_buf, "{{ADMIN_URL}}", admin_url);
    template_buf = apply(template_buf, "{{LOW_PRIV_TOKEN}}", low_priv);
    /* checkbox attribute -- not inside a value="", so no escaping needed */
    {
        char *next = replace_all(template_buf, "{{INTRUSIVE_CHECKED}}", intrusive ? "checked" : "");
        free(template_buf);
        template_buf = next;
    }

    FILE *out = fopen(out_path, "wb");
    if (!out) {
        fprintf(stderr, "Could not open %s for writing.\n", out_path);
        return 1;
    }
    fputs(template_buf, out);
    fclose(out);

    printf("\nTemplate used: %s\n", found_at);
    printf("Wrote %s\n", out_path);
    printf("Open it in a browser to configure/run the scan (make sure the backend\n"
           "is running and reachable at %s first).\n", api_base);

    return 0;
}
