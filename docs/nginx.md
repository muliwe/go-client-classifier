# NGINX setup for TLS and HTTP/2 fingerprint research

This document describes a local nginx setup for the transport-level HTTP client fingerprinting research project.

Goals:

* TLS termination with TLS context passed to the Go backend
* HTTP/2 fingerprint extraction
* JA3 (optional)
* TLS passthrough mode
* Integration with certbot (Let's Encrypt)
* Unified fingerprint data delivery via headers

---

# Architecture

```
client
  ↓
nginx
  ├─ 443  → TLS termination + JA3 + H2 fingerprint → X-FP-* headers → Go HTTP :8080 (collector uses headers)
  │         OR: stream on 443 + SNI → Go HTTPS :8443 (passthrough, Go terminates TLS; other hosts → http on :8440)
  └─ 8444 → TLS passthrough                        → Go HTTPS :8443 (direct TLS to Go)
```

---

# Requirements

System: Ubuntu/Debian
Privileges: root or sudo
Domain: reachable for certbot

---

# Installing dependencies

```
sudo apt update
sudo apt install -y \
 build-essential \
 git \
 libpcre3 libpcre3-dev \
 zlib1g zlib1g-dev \
 libssl-dev \
 certbot \
 libxml2-dev \
 libxslt1-dev \
 libgd-dev \
 libgeoip-dev \
 libpam0g-dev
```

---

# Building nginx with JA3 and HTTP/2 fingerprint

**Important:** Both JA3 and HTTP/2 fingerprint require **patching OpenSSL and nginx**. There is no “add one module to stock nginx” path that gives JA3 — the module code calls OpenSSL APIs that only exist in the patched OpenSSL. See [Wallarm: Enabling JA3](https://docs.wallarm.com/admin-en/enabling-ja3/) and [phuslu/nginx-ssl-fingerprint](https://github.com/phuslu/nginx-ssl-fingerprint): *“In both modules, we need to patch OpenSSL and NGINX.”*

Recommended approach: **[phuslu/nginx-ssl-fingerprint](https://github.com/phuslu/nginx-ssl-fingerprint)** — one module for JA3 and HTTP/2, with a clear [support matrix](https://github.com/phuslu/nginx-ssl-fingerprint#support-matrix) (nginx 1.20–1.27 × OpenSSL 1.1.1 / 3.0 / 3.1 / 3.2). Build from **clean clones**, then replace the system binary if needed.

---

## Working recipe (phuslu: JA3 + HTTP/2)

Use **one** OpenSSL + nginx version pair from the support matrix. Example: **OpenSSL 3.2** and **nginx 1.24** (or 1.25). All commands from a single directory (e.g. `/usr/local/src`).

**1. Clone OpenSSL, nginx, fingerprint module (and optionally auth_pam)**

```bash
cd /usr/local/src
sudo git clone -b openssl-3.2 --depth=1 https://github.com/openssl/openssl.git openssl-3.2
sudo git clone https://github.com/nginx/nginx.git nginx
sudo git clone https://github.com/phuslu/nginx-ssl-fingerprint.git nginx-ssl-fingerprint
sudo git clone https://github.com/sto/ngx_http_auth_pam_module.git ngx_http_auth_pam_module
cd nginx
sudo git checkout release-1.24.0
```

(If your system nginx is 1.25.x, use `release-1.25.3` and the patch `nginx-1.25.patch` below.)

**2. Patch OpenSSL and nginx**

JA3 needs the patched OpenSSL; the nginx patch adds the callback that uses it. Without both patches you get errors like `implicit declaration of function 'SSL_client_hello_get_ja3_data'`.

```bash
cd /usr/local/src
sudo patch -p1 -d openssl-3.2 < nginx-ssl-fingerprint/patches/openssl.openssl-3.2.patch
sudo patch -p1 -d nginx < nginx-ssl-fingerprint/patches/nginx-1.24.patch
```

For nginx 1.25 use `nginx-1.25.patch`; for 1.27 use `nginx-1.27.patch` and check the repo for the matching OpenSSL branch/patch.

**3. Configure and build nginx**

Point nginx at the **patched** OpenSSL source and add the fingerprint module. Add `--add-dynamic-module=.../ngx_http_auth_pam_module` if you cloned it (builds `ngx_http_auth_pam_module.so` for `modules-enabled`). Do **not** use the system OpenSSL for this build.

```bash
cd /usr/local/src/nginx
./auto/configure \
  --with-openssl=$(pwd)/../openssl-3.2 \
  --add-module=$(pwd)/../nginx-ssl-fingerprint \
  --add-dynamic-module=$(pwd)/../ngx_http_auth_pam_module \
  --with-http_ssl_module \
  --with-http_v2_module \
  --with-stream \
  --with-stream_ssl_module \
  --with-stream_ssl_preread_module \
  --with-http_realip_module \
  --prefix=/usr/local/nginx \
  --modules-path=/usr/local/nginx/modules
make -j$(nproc)
sudo make install
```

If you did **not** clone `ngx_http_auth_pam_module`, omit the `--add-dynamic-module=...ngx_http_auth_pam_module` line and disable the PAM config: `sudo mv /etc/nginx/modules-enabled/50-mod-http-auth-pam.conf /etc/nginx/modules-enabled/50-mod-http-auth-pam.conf.bak`.

Result: nginx in `/usr/local/nginx/` with JA3 and HTTP/2 fingerprint variables (`$http_ssl_ja3`, `$http_ssl_ja3_hash`, `$http2_fingerprint`). Use this binary and your existing config (or symlink `/usr/local/nginx/sbin/nginx` into PATH).

**4. Optional: replace the system nginx binary**

If you want to keep using the distro’s paths and config (e.g. `/etc/nginx/`, `nginx -V` showing the same prefix), build with that prefix and sbin path, then replace the binary:

```bash
# When configuring, use the same prefix/sbin as the package, e.g.:
./auto/configure \
  --with-openssl=$(pwd)/../openssl-3.2 \
  --add-module=$(pwd)/../nginx-ssl-fingerprint \
  --with-http_ssl_module --with-http_v2_module \
  --with-stream --with-stream_ssl_module --with-stream_ssl_preread_module \
  --with-http_realip_module \
  --prefix=/usr/share/nginx \
  --sbin-path=/usr/sbin/nginx \
  --conf-path=/etc/nginx/nginx.conf \
  --modules-path=/usr/lib/nginx/modules
# ... add other paths from `nginx -V` if you need them
make -j$(nproc)
sudo cp /usr/sbin/nginx /usr/sbin/nginx.bak
sudo cp objs/nginx /usr/sbin/nginx
sudo nginx -t && sudo nginx -s reload
```

You do **not** need to replicate every Ubuntu configure flag (geoip, image_filter, xslt, etc.) unless you use those features. For fingerprinting you only need the SSL, HTTP/2, stream, and realip options above.

---

## Why not “add module to existing build”

- **Xetera/nginx-http2-fingerprint** is a full nginx **fork**, not an add-on module.
- **phuslu** and **fooinha/nginx-ssl-ja3** both require **patched OpenSSL + patched nginx**. Building with the system (unpatched) OpenSSL and only adding the module leads to `implicit declaration of function 'SSL_client_hello_get_ja3_data'`. So the only reliable approach is: clone OpenSSL and nginx, apply both patches, then configure with `--with-openssl=<patched_openssl>` and `--add-module=...`.

---

# Certbot certificates

Obtaining a certificate:

```
sudo certbot certonly --standalone -d example.com
```

Certificate paths:

```
/etc/letsencrypt/live/example.com/fullchain.pem
/etc/letsencrypt/live/example.com/privkey.pem
```

---

# Certificate auto-renewal

```
sudo crontab -e
```

```
0 3 * * * /usr/bin/certbot renew --quiet --post-hook "/usr/sbin/nginx -s reload"
```

---

# nginx configuration

**Main config** — ensure the `http` block in `/etc/nginx/nginx.conf` includes site files (Debian/Ubuntu default):

```
http {
    include       mime.types;
    default_type  application/octet-stream;
    sendfile      on;

    log_format fp '$remote_addr $ssl_protocol $ssl_cipher $http2_fingerprint';
    access_log   /var/log/nginx/access.log fp;

    include /etc/nginx/sites-enabled/*;
}
```

**Site file** — create `/etc/nginx/sites-available/your.domain.tld`:

```
server {
    listen 80;
    server_name your.domain.tld;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your.domain.tld;

    ssl_certificate     /etc/letsencrypt/live/your.domain.tld/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your.domain.tld/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;

    location / {
        proxy_pass http://127.0.0.1:8080;

        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;

        # TLS context
        proxy_set_header X-FP-TLS-Version   $ssl_protocol;
        proxy_set_header X-FP-TLS-Cipher    $ssl_cipher;
        proxy_set_header X-FP-TLS-ALPN      $ssl_alpn_protocol;
        proxy_set_header X-FP-TLS-SNI       $ssl_server_name;

        # JA3 (if module is built)
        proxy_set_header X-FP-JA3 $ssl_ja3; # form phuslu fork $http_ssl_ja3

        # HTTP/2 fingerprint
        proxy_set_header X-FP-H2 $http2_fingerprint;

        # prevent header spoofing
        proxy_set_header X-Internal-Proxy "1";
    }
}
```

Enable the site and reload:

```
sudo ln -s /etc/nginx/sites-available/your.domain.tld /etc/nginx/sites-enabled/
sudo nginx -t && sudo nginx -s reload
```

---

# TLS passthrough configuration

**Requirement:** The `stream { }` directive requires nginx to be built with the stream module. On **Ubuntu**, the default `nginx` package may not include it (you get `unknown directive "stream"` even when the block is at top level). Install **nginx-full**, which includes Stream:

```bash
sudo apt install nginx-full
```

Confirm with `nginx -V 2>&1` that the binary has stream support, then `sudo nginx -t && sudo nginx -s reload`.

**Important:** Stream config must **not** be in `sites-available` or `sites-enabled` — those are included inside `http { }`, so nginx would parse it as HTTP and fail with `"proxy_pass" directive is not allowed here`. Use a separate path and include it only from a top-level `stream { }` block.

**1. Create the stream config** in a path that is **not** under `sites-enabled`, for example:

`/etc/nginx/stream-available/your.domain.tld` (create the directory if needed: `sudo mkdir -p /etc/nginx/stream-available`)

```
upstream go_tls_backend {
    server 127.0.0.1:8443;
}

server {
    listen 8444;
    proxy_pass go_tls_backend;
    proxy_protocol on;
}
```

**2. Include it from the top-level `stream { }` block** in `nginx.conf` (same level as `http { }`, not inside it). Edit `/etc/nginx/nginx.conf` and add, or add to an existing `stream` block:

```
stream {
    include /etc/nginx/stream-available/your.domain.tld;
}
```

**3. If you previously put this file in `sites-enabled`**, remove it so it is not loaded in `http` context:

```
sudo rm /etc/nginx/sites-enabled/your.domain.tld
# keep the stream file only in stream-available and include it from stream { }
```

Then run `sudo nginx -t` and `sudo nginx -s reload`.

In this mode nginx does not terminate TLS and does not extract HTTP/2 fingerprint.

---

# Stream on port 443 (Go terminates TLS)

When you need **Go to terminate TLS** for your domain on the default HTTPS port (443) while other domains still use 443, nginx cannot have both `http` and `stream` listening on 443 — only one context can bind the port. The solution is **stream on 443** with SNI-based routing: your domain → Go :8443 (passthrough), everything else → nginx `http` on an internal port (e.g. 8440).

**1. Move other HTTPS servers from 443 to an internal port**

In all site configs under `sites-enabled` / `conf.d` that use `listen 443 ssl`, change to:

```nginx
listen 8440 ssl proxy_protocol;
```

(Use a port that is not used by Go, e.g. 8440; 8443/8444 are Go and passthrough.)

Because the stream server below sends PROXY protocol to **both** backends (8443 and 8440), the nginx **http** server on 8440 must accept it: add `proxy_protocol` to `listen`, then set the real client IP from the PROXY header. In the same config file(s), inside the `http { }` block (or in each server that uses 8440), add:

```nginx
set_real_ip_from 127.0.0.1;
real_ip_header proxy_protocol;
```

(Requires nginx built with `--with-http_realip_module`, which is included in many packages.) Then nginx http on 8440 will parse the PROXY header and use the client address for `$remote_addr` and access logs.

List files that still have `listen` with 443:

```bash
sudo grep -rl "listen.*443" /etc/nginx/
```

**2. Add stream block for 443 in nginx.conf**

In the top-level `stream { }` block (same level as `http { }`), add SNI routing and a server listening on 443:

```nginx
stream {
    map $ssl_preread_server_name $backend_443 {
        your.domain.tld  127.0.0.1:8443;
        default          127.0.0.1:8440;
    }

    server {
        listen 443;
        proxy_pass $backend_443;
        ssl_preread on;
        proxy_protocol on;   # optional: send client IP to Go; requires PROXY_PROTOCOL=1 on the Go service
    }

    include /etc/nginx/streams-available/your.domain.tld;   # optional: e.g. 8444 passthrough
}
```

**Real client IP for stream:** The stream server above has `proxy_protocol on`, so it sends the PROXY protocol header to **both** backends (Go :8443 and nginx http :8440). Nginx http understands PROXY: use `listen 8440 ssl proxy_protocol` and `real_ip_header proxy_protocol` as in step 1 so that access logs on 8440 show the real client IP. For Go, start the service with `PROXY_PROTOCOL=1` (or `true`) so it parses the PROXY header and uses the client address for logging. If you ever run without `proxy_protocol on` in stream (e.g. only one backend), leave `PROXY_PROTOCOL` unset on the Go side so direct TLS still works.

**3. Proxy HTTP (port 80) to Go**

So that `http://your.domain.tld` is also served by the Go app, add an `http` server block (e.g. in the same site file or in a dedicated one under `sites-enabled`):

```nginx
server {
    listen 80;
    server_name your.domain.tld;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Internal-Proxy "1";
    }
}
```

**Real client IP in logs:** The Go server uses `X-Forwarded-For` (or `X-Real-IP`) when the request is from localhost or when `X-Internal-Proxy` is `"1"`, so logs and JSONL show the real client IP instead of the proxy address. For both HTTP (port 80) and TLS termination (443 → http to Go), set these headers as above.

**4. Reload**

```bash
sudo nginx -t && sudo nginx -s reload
```

Result: `http://your.domain.tld` (port 80) is proxied to Go :8080; `https://your.domain.tld` (port 443) is forwarded to Go :8443; Go terminates TLS and serves its certificate. Other hostnames on 443 are forwarded to 127.0.0.1:8440 where nginx `http` terminates TLS as before. Clients still connect to port 443 for all domains.

References: [nginx stream ssl_preread](https://nginx.org/en/docs/stream/ngx_stream_ssl_preread_module.html), [ServerFault: selective TLS passthrough](https://serverfault.com/questions/999728/nginx-selective-tls-passthrough-reverse-proxy-based-on-sni).

---

# Running nginx

**Test configuration** (validate syntax and paths without starting or reloading):

```
sudo nginx -t
```

On a source install, use the full path: `sudo /usr/local/nginx/sbin/nginx -t`. Run this after editing configs and before `start` or `reload`.

**Start:**

```
sudo nginx
# or: sudo /usr/local/nginx/sbin/nginx
```

**Reload** (after testing with `nginx -t`):

```
sudo nginx -s reload
```

**Stop:**

```
sudo nginx -s stop
```

---

# Verification

HTTP/2 request:

```
curl --http2 -k https://example.com
```

Checking headers in the Go backend:

```
X-FP-TLS-Version
X-FP-TLS-Cipher
X-FP-TLS-ALPN
X-FP-JA3
X-FP-H2
```

---

# Reading fingerprint in Go

The collector uses these headers when `X-Internal-Proxy` is `"1"` (see [METHODOLOGY.md](METHODOLOGY.md) Appendix F). JA3 and H2 are also used for cross-validation (TLS vs User-Agent, H2 vs UA; see Appendix G).

```go
if r.Header.Get("X-Internal-Proxy") == "1" {
    tlsVersion := r.Header.Get("X-FP-TLS-Version")
    tlsCipher  := r.Header.Get("X-FP-TLS-Cipher")
    ja3        := r.Header.Get("X-FP-JA3")
    h2fp       := r.Header.Get("X-FP-H2")

    _ = tlsVersion
    _ = tlsCipher
    _ = ja3
    _ = h2fp
}
```

---

# Lab comparison mode

Using both modes is recommended:

```
443  → TLS terminate → Go HTTP
8444 → TLS passthrough → Go HTTPS
```

This allows comparing:

* JA4 (Go)
* JA3 (nginx)
* HTTP/2 fingerprint
* Cross-layer consistency

---

# Logging

Available in access_log:

```
$ssl_protocol
$ssl_cipher
$ssl_ja3/$http_ssl_ja3
$http2_fingerprint
$remote_addr
```

These values should be stored in a dataset for later analysis.

---

# HTTP/2 fingerprint: what the module provides

A compatible HTTP/2 fingerprint is exposed as `$http2_fingerprint` by [Xetera/nginx-http2-fingerprint](https://github.com/Xetera/nginx-http2-fingerprint) (when building from that fork) or by [phuslu/nginx-ssl-fingerprint](https://github.com/phuslu/nginx-ssl-fingerprint) (add-on module). It encodes SETTINGS (including INITIAL_WINDOW_SIZE), PRIORITY, and flow-control/window behaviour per Akamai’s method. Pass it to the Go backend as `X-FP-H2`. The Go server parses this string (format `SETTINGS|WINDOW_UPDATE|PRIORITY|...`) into structured fields (SETTINGS map, initial window, priority) for logging and signals; see [METHODOLOGY.md](METHODOLOGY.md) Phase 2 and Appendix F.

Any future “extended” H2 statistics (e.g. separate variables per frame type) would still be collected via nginx modules rather than Go: there are no mature passive HTTP/2 fingerprinting libraries in Go, and nginx already parses H2 at the edge.

---

# Notes

1. HTTP/2 fingerprint is only available with TLS termination.
2. With TLS passthrough nginx does not see HTTP/2 frames.
3. Fingerprint headers must only be trusted when coming from the trusted proxy.
4. Do not use these headers directly from untrusted (external) traffic.
5. **Real client IP in logs:** Set `X-Forwarded-For` (or `X-Real-IP`) so the Go server logs the real client IP. When the proxy is not on localhost, also set `X-Internal-Proxy "1"` so the backend trusts the forwarded IP (same as for fingerprint headers).
