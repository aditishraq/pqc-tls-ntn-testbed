/*
 * hsclient — TLS 1.3 measurement client for the PQC-NTN testbed.
 * Built inside the testbed image against the image's own OpenSSL (+ oqsprovider).
 *
 *   hsclient hs    HOST PORT CAFILE GROUP HOSTNAME N TIMEOUT_S
 *       N sequential full handshakes, each on a NEW TCP connection, no resumption.
 *   hsclient conc  HOST PORT CAFILE GROUP HOSTNAME K TIMEOUT_S
 *       K threads released together by a pthread barrier, one handshake each.
 *   hsclient bench KEYFILE SECONDS WARMUP
 *       in-process keygen / sign / verify timing for the key type in KEYFILE,
 *       using the provider that decodes KEYFILE (the one s_server signs with).
 *
 * Output: one JSON object per line.
 *
 * Timers (CLOCK_MONOTONIC):
 *   t_tcp_ms    socket()+connect() start  -> connect() returns (TCP established)
 *   t_tls_ms    connect() returns         -> SSL_connect() returns 1 (client Finished sent)
 *   t_total_ms  socket() start            -> SSL_connect() returns 1  (= tcp + tls)
 *   t_app_ms    SSL_connect() returns     -> first HTTP response bytes read (not part of handshake)
 *   t_elapsed_ms socket() start           -> end of the attempt, success or failure (timeouts)
 * Connection close is never timed.
 * Byte counters are snapshotted when SSL_connect() returns: TLS record bytes only
 * (TCP payload), excluding TCP/IP headers and anything after the handshake.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

static __thread int alert_recv = -1, alert_sent = -1;   /* TLS alert numbers */

static void info_cb(const SSL *s, int where, int ret) {
    (void)s;
    if (!(where & SSL_CB_ALERT)) return;
    if (where & SSL_CB_READ) alert_recv = ret & 0xff;     /* sent by the server */
    else alert_sent = ret & 0xff;                          /* sent by this client */
}

typedef struct {
    const char *host, *cafile, *group, *name;
    int port, timeout_s;
} cfg_t;

typedef struct {
    int trial, ok_tcp, ok_tls, ok_app, alert, alert_sent, verify_code, hostname_ok;
    double t_tcp, t_tls, t_total, t_app, t_start, t_elapsed;
    unsigned long long c2s, s2c;
    char stage[8], err[256], verify_msg[96], proto[16], cipher[64], group[64], sig[64], srand[65];
} trial_t;

static SSL_CTX *make_ctx(const cfg_t *c) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    if (!SSL_CTX_set1_groups_list(ctx, c->group)) { fprintf(stderr, "bad group %s\n", c->group); exit(2); }
    if (!SSL_CTX_load_verify_locations(ctx, c->cafile, NULL)) { fprintf(stderr, "bad CA %s\n", c->cafile); exit(2); }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);                 /* no resumption material */
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_info_callback(ctx, info_cb);
    return ctx;
}

static void one_trial(SSL_CTX *ctx, const cfg_t *c, trial_t *r, pthread_barrier_t *bar) {
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(c->port)};
    struct timeval tv = {.tv_sec = c->timeout_s};
    SSL *ssl = NULL;
    X509 *peer = NULL;
    int fd;

    inet_pton(AF_INET, c->host, &sa.sin_addr);
    alert_recv = alert_sent = -1;
    r->verify_code = -1;
    strcpy(r->stage, "tcp");

    if (bar) pthread_barrier_wait(bar);
    double t0 = now_ms();
    r->t_start = t0;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        snprintf(r->err, sizeof r->err, "connect: %s", strerror(errno));
        goto done;
    }
    double t1 = now_ms();
    r->ok_tcp = 1;
    r->t_tcp = t1 - t0;

    strcpy(r->stage, "tls");
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, c->name);
    SSL_set1_host(ssl, c->name);                              /* hostname/SAN check in verify */
    int rc = SSL_connect(ssl);
    double t2 = now_ms();
    r->c2s = BIO_number_written(SSL_get_wbio(ssl));
    r->s2c = BIO_number_read(SSL_get_rbio(ssl));
    r->verify_code = (int)SSL_get_verify_result(ssl);
    snprintf(r->verify_msg, sizeof r->verify_msg, "%s", X509_verify_cert_error_string(r->verify_code));
    snprintf(r->proto, sizeof r->proto, "%s", SSL_get_version(ssl));
    const SSL_CIPHER *ciph = SSL_get_current_cipher(ssl);
    snprintf(r->cipher, sizeof r->cipher, "%s", ciph ? SSL_CIPHER_get_name(ciph) : "NONE");
    const char *g = SSL_get0_group_name(ssl);
    snprintf(r->group, sizeof r->group, "%s", g ? g : "<NULL>");
    const char *sg = NULL;
    if (SSL_get0_peer_signature_name(ssl, &sg) == 1 && sg) snprintf(r->sig, sizeof r->sig, "%s", sg);
    peer = SSL_get1_peer_certificate(ssl);
    r->hostname_ok = peer ? X509_check_host(peer, c->name, 0, 0, NULL) == 1 : 0;
    if (rc != 1) {
        ERR_error_string_n(ERR_peek_last_error(), r->err, sizeof r->err);
        goto done;
    }
    r->ok_tls = 1;
    r->t_tls = t2 - t1;
    r->t_total = t2 - t0;
    unsigned char sr[32];
    SSL_get_server_random(ssl, sr, sizeof sr);
    for (int i = 0; i < 32; i++) sprintf(r->srand + 2 * i, "%02x", sr[i]);

    strcpy(r->stage, "app");                                  /* small application exchange */
    const char req[] = "GET / HTTP/1.0\r\n\r\n";
    char buf[64] = {0};
    if (SSL_write(ssl, req, sizeof req - 1) > 0 && SSL_read(ssl, buf, sizeof buf - 1) > 0
        && strncmp(buf, "HTTP/1.0 200", 12) == 0) {
        r->ok_app = 1;
        r->t_app = now_ms() - t2;
        strcpy(r->stage, "ok");
    } else {
        ERR_error_string_n(ERR_peek_last_error(), r->err, sizeof r->err);
    }
    SSL_shutdown(ssl);                                       /* not timed, not awaited */
done:
    r->t_elapsed = now_ms() - t0;                           /* whole attempt, incl. failures */
    r->alert = alert_recv;
    r->alert_sent = alert_sent;
    X509_free(peer);
    SSL_free(ssl);
    close(fd);
    ERR_clear_error();
}

static void print_trial(const char *mode, const trial_t *r) {
    printf("{\"mode\":\"%s\",\"trial\":%d,\"stage\":\"%s\",\"ok_tcp\":%d,\"ok_tls\":%d,\"ok_app\":%d,"
           "\"t_start_ms\":%.3f,\"t_elapsed_ms\":%.3f,\"t_tcp_ms\":%.3f,\"t_tls_ms\":%.3f,\"t_total_ms\":%.3f,\"t_app_ms\":%.3f,"
           "\"bytes_c2s\":%llu,\"bytes_s2c\":%llu,\"alert_recv\":%d,\"alert_sent\":%d,\"verify_code\":%d,\"verify_msg\":\"%s\","
           "\"hostname_ok\":%d,\"protocol\":\"%s\",\"cipher\":\"%s\",\"group\":\"%s\",\"peer_sig\":\"%s\","
           "\"server_random\":\"%s\",\"error\":\"%s\"}\n",
           mode, r->trial, r->stage, r->ok_tcp, r->ok_tls, r->ok_app, r->t_start, r->t_elapsed, r->t_tcp, r->t_tls,
           r->t_total, r->t_app, r->c2s, r->s2c, r->alert, r->alert_sent, r->verify_code, r->verify_msg,
           r->hostname_ok, r->proto, r->cipher, r->group, r->sig, r->srand, r->err);
}

typedef struct { SSL_CTX *ctx; const cfg_t *c; trial_t *r; pthread_barrier_t *bar; } targ_t;

static void *thread_fn(void *p) {
    targ_t *a = p;
    one_trial(a->ctx, a->c, a->r, a->bar);
    return NULL;
}

/* ── crypto microbenchmark ───────────────────────────────────────────── */

typedef int (*op_fn)(void *);
typedef struct { EVP_PKEY *key; const char *md; const char *type; const char *prov;
                 unsigned char sig[16384]; size_t siglen; } bctx_t;
static const unsigned char MSG[128] = "PQC-NTN microbenchmark message: TLS 1.3 CertificateVerify-sized input ..........";

static int op_keygen(void *p) {
    bctx_t *b = p;
    char propq[64];
    snprintf(propq, sizeof propq, "provider=%s", b->prov);
    EVP_PKEY *k = strcmp(b->type, "EC") == 0
        ? EVP_PKEY_Q_keygen(NULL, propq, "EC", "P-256")
        : EVP_PKEY_Q_keygen(NULL, propq, b->type);
    EVP_PKEY_free(k);
    return k != NULL;
}

static int op_sign(void *p) {
    bctx_t *b = p;
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    b->siglen = sizeof b->sig;
    int ok = EVP_DigestSignInit_ex(m, NULL, b->md, NULL, NULL, b->key, NULL) == 1
          && EVP_DigestSign(m, b->sig, &b->siglen, MSG, sizeof MSG) == 1;
    EVP_MD_CTX_free(m);
    return ok;
}

static int op_verify(void *p) {
    bctx_t *b = p;
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    int ok = EVP_DigestVerifyInit_ex(m, NULL, b->md, NULL, NULL, b->key, NULL) == 1
          && EVP_DigestVerify(m, b->sig, b->siglen, MSG, sizeof MSG) == 1;
    EVP_MD_CTX_free(m);
    return ok;
}

static void time_op(const char *name, op_fn f, bctx_t *b, double seconds, int warmup) {
    for (int i = 0; i < warmup; i++)
        if (!f(b)) { printf("{\"op\":\"%s\",\"type\":\"%s\",\"error\":\"op failed\"}\n", name, b->type); return; }
    long n = 0;
    double t0 = now_ms(), t;
    do { f(b); n++; t = now_ms(); } while (t - t0 < seconds * 1000 || n < 100);
    printf("{\"op\":\"%s\",\"type\":\"%s\",\"provider\":\"%s\",\"md\":\"%s\",\"warmup\":%d,"
           "\"ops\":%ld,\"total_s\":%.4f,\"ms_per_op\":%.6f,\"sig_bytes\":%zu}\n",
           name, b->type, b->prov, b->md ? b->md : "none", warmup, n, (t - t0) / 1000, (t - t0) / n, b->siglen);
}

static int bench(const char *keyfile, double seconds, int warmup) {
    FILE *fp = fopen(keyfile, "r");
    if (!fp) { perror(keyfile); return 2; }
    bctx_t *b = calloc(1, sizeof *b);
    b->key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!b->key) { ERR_print_errors_fp(stderr); return 2; }
    b->type = EVP_PKEY_get0_type_name(b->key);
    b->prov = OSSL_PROVIDER_get0_name(EVP_PKEY_get0_provider(b->key));
    b->md = strcmp(b->type, "EC") == 0 ? "SHA256" : NULL;
    if (!op_sign(b)) { b->md = "SHA256"; ERR_clear_error(); }  /* some composites need a digest */
    time_op("sign", op_sign, b, seconds, warmup);            /* sign first: verify needs b->sig */
    time_op("verify", op_verify, b, seconds, warmup);
    time_op("keygen", op_keygen, b, seconds, warmup);
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 5 && strcmp(argv[1], "bench") == 0)
        return bench(argv[2], atof(argv[3]), atoi(argv[4]));
    if (argc < 9) {
        fprintf(stderr, "usage: hsclient hs|conc HOST PORT CAFILE GROUP HOSTNAME N TIMEOUT_S\n"
                        "       hsclient bench KEYFILE SECONDS WARMUP\n");
        return 2;
    }
    cfg_t c = {argv[2], argv[4], argv[5], argv[6], atoi(argv[3]), atoi(argv[8])};
    int n = atoi(argv[7]);
    SSL_CTX *ctx = make_ctx(&c);
    trial_t *r = calloc(n, sizeof *r);

    if (strcmp(argv[1], "hs") == 0) {
        for (int i = 0; i < n; i++) {
            r[i].trial = i + 1;
            one_trial(ctx, &c, &r[i], NULL);
            print_trial("hs", &r[i]);
            fflush(stdout);
        }
    } else {
        pthread_t *th = calloc(n, sizeof *th);
        targ_t *a = calloc(n, sizeof *a);
        pthread_barrier_t bar;
        pthread_barrier_init(&bar, NULL, n);
        for (int i = 0; i < n; i++) {
            r[i].trial = i + 1;
            a[i] = (targ_t){ctx, &c, &r[i], &bar};
            pthread_create(&th[i], NULL, thread_fn, &a[i]);
        }
        for (int i = 0; i < n; i++) pthread_join(th[i], NULL);
        for (int i = 0; i < n; i++) print_trial("conc", &r[i]);
    }
    SSL_CTX_free(ctx);
    return 0;
}
