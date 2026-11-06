/*
 * VAShield IP/Port patcher
 * ------------------------
 * Asks for a target IP (or hostname) and port, then rewrites ONLY the
 * value="..." attributes of the #targetUrl and #ports inputs inside
 * index.html. Everything else in the file -- every <script> function,
 * every class, every other tag -- is copied through byte-for-byte,
 * untouched.
 *
 * It does this by locating id="targetUrl" / id="ports" in the file text
 * and doing a surgical replace of just the following value="..." field,
 * rather than rebuilding the file from a template. If those input ids
 * aren't found (e.g. you point it at a different/edited HTML file), it
 * says so and leaves the file exactly as it was.
 *
 * This program does not talk to the network and does not bypass the
 * backend's ownership check -- it only edits two attribute values in a
 * local HTML file.
 *
 * Build (Linux/macOS/WSL, or Windows with MinGW/MSYS2 gcc):
 *   gcc -O2 -o configure_ip_port configure_ip_port.c
 *   (on Windows this produces configure_ip_port.exe automatically)
 *
 * Build (Windows, MSVC "Developer Command Prompt"):
 *   cl configure_ip_port.c
 *
 * Run:
 *   ./configure_ip_port                 (uses defaults: index.html -> vashield_run.html)
 *   ./configure_ip_port in.html out.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LINE_MAX_LEN 256

static void trim_newline(char *s) {
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) s[--n] = '\0';
}

static char *ask(const char *prompt, const char *def) {
    char buf[LINE_MAX_LEN];
    printf("%s [%s]: ", prompt, def);
    fflush(stdout);
    if (!fgets(buf, sizeof(buf), stdin)) buf[0] = '\0';
    trim_newline(buf);
    const char *chosen = (buf[0] != '\0') ? buf : def;
    char *out = malloc(strlen(chosen) + 1);
    if (!out) { fprintf(stderr, "out of memory\n"); exit(1); }
    strcpy(out, chosen);
    return out;
}

/* HTML-attribute-safe escaping (value lands inside value="..."). */
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

static char *read_file(const char *path) {
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
    return buf;
}

/*
 * Finds id="<input_id>" in `html`, then the value="..." that follows it,
 * and replaces just the text inside those quotes with `new_value`
 * (HTML-escaped). Every other byte in the file -- including all
 * <script> function bodies -- is copied through unchanged.
 * Returns a freshly malloc'd buffer; frees the one passed in.
 */
static char *set_input_value(char *html, const char *input_id, const char *new_value) {
    char needle[128];
    snprintf(needle, sizeof(needle), "id=\"%s\"", input_id);

    char *id_pos = strstr(html, needle);
    if (!id_pos) {
        fprintf(stderr, "Warning: could not find id=\"%s\" in the HTML -- left unchanged.\n", input_id);
        return html;
    }
    const char *marker = "value=\"";
    char *val_pos = strstr(id_pos, marker);
    if (!val_pos) {
        fprintf(stderr, "Warning: found id=\"%s\" but no value=\"...\" after it -- left unchanged.\n", input_id);
        return html;
    }
    char *val_start = val_pos + strlen(marker);
    char *val_end = strchr(val_start, '"');
    if (!val_end) {
        fprintf(stderr, "Warning: unterminated value=\" for id=\"%s\" -- left unchanged.\n", input_id);
        return html;
    }

    char *escaped = html_escape(new_value);
    size_t prefix_len = (size_t)(val_start - html);
    size_t suffix_len = strlen(val_end);          /* includes the closing quote onward */
    size_t out_len = prefix_len + strlen(escaped) + suffix_len;

    char *out = malloc(out_len + 1);
    if (!out) { fprintf(stderr, "out of memory\n"); exit(1); }
    memcpy(out, html, prefix_len);
    memcpy(out + prefix_len, escaped, strlen(escaped));
    memcpy(out + prefix_len + strlen(escaped), val_end, suffix_len + 1); /* +1 for NUL */

    free(escaped);
    free(html);
    return out;
}

int main(int argc, char **argv) {
    const char *in_path  = (argc > 1) ? argv[1] : "../frontend/index.html";
    const char *out_path = (argc > 2) ? argv[2] : "vashield_run.html";

    printf("=== VAShield IP/Port patcher ===\n");
    printf("Only the Target base URL and Ports fields are changed.\n");
    printf("Nothing in the <script> logic is touched.\n\n");

    char *ip   = ask("Target IP or hostname", "127.0.0.1");
    char *port = ask("Target port", "5055");

    char target_url[LINE_MAX_LEN];
    snprintf(target_url, sizeof(target_url), "http://%s:%s", ip, port);

    char *html = read_file(in_path);
    if (!html) {
        /* fall back to a couple of likely alternate paths */
        const char *alt[] = { "frontend/index.html", "index.html" };
        for (size_t i = 0; i < sizeof(alt) / sizeof(alt[0]) && !html; i++)
            html = read_file(alt[i]);
    }
    if (!html) {
        fprintf(stderr, "\nCould not find %s (or the usual fallback paths).\n"
                        "Run this from vashield/tools, or pass the path explicitly:\n"
                        "  %s <path-to-index.html> <output.html>\n", in_path, argv[0]);
        return 1;
    }

    html = set_input_value(html, "targetUrl", target_url);
    html = set_input_value(html, "ports", port);

    FILE *out = fopen(out_path, "wb");
    if (!out) {
        fprintf(stderr, "Could not open %s for writing.\n", out_path);
        free(html);
        return 1;
    }
    fputs(html, out);
    fclose(out);
    free(html);

    printf("\nWrote %s\n", out_path);
    printf("Target base URL set to: %s\n", target_url);
    printf("Ports set to:           %s\n", port);
    printf("Open %s in a browser to run the scan.\n", out_path);
    return 0;
}
