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
 certbot
```

---

# Building nginx with fingerprint modules

## 1. nginx source

```
git clone https://github.com/nginx/nginx.git
cd nginx
```

## 2. HTTP/2 fingerprint module

```
git clone https://github.com/Xetera/nginx-http2-fingerprint.git
```

This module implements [Akamai’s passive HTTP/2 fingerprinting](https://blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf): one variable `$http2_fingerprint` contains SETTINGS (incl. INITIAL_WINDOW_SIZE), PRIORITY, and flow-control/window behaviour (RFC 7540 §10.8). Forward it to the backend as `X-FP-H2`.

## 3. JA3 module (optional)

```
git clone https://github.com/fooinha/nginx-ssl-ja3.git
```

---

## 4. Build configuration

```
./auto/configure \
 --prefix=/usr/local/nginx \
 --with-http_ssl_module \
 --with-http_v2_module \
 --with-stream \
 --with-stream_ssl_preread_module \
 --add-module=../nginx-http2-fingerprint \
 --add-module=../nginx-ssl-ja3
```

```
make -j$(nproc)
sudo make install
```

---

# Adding fingerprint modules when nginx is already installed

If nginx was installed from a package (e.g. `apt install nginx`), you need to rebuild the binary with the same build options plus the fingerprint modules, then replace the system binary.

**1. Get the installed nginx version and its configure arguments**

```
nginx -V 2>&1
```

Copy the entire output. You will need the version (first line) and the `configure arguments:` line.

**2. Clone nginx source of the same (or compatible) version**

```
cd /usr/local/src   # or any directory you prefer
sudo git clone https://github.com/nginx/nginx.git
cd nginx
sudo git checkout release-1.27.2   # replace with your version, e.g. release-1.26.1 or mainline
```

Match the major.minor from `nginx -V` (e.g. `nginx/1.27.2` → `release-1.27.2`).

**3. Clone the fingerprint modules next to the nginx directory**

```
sudo git clone https://github.com/Xetera/nginx-http2-fingerprint.git /usr/local/src/nginx-http2-fingerprint
sudo git clone https://github.com/fooinha/nginx-ssl-ja3.git /usr/local/src/nginx-ssl-ja3
```

**4. Configure with the same arguments as the package, plus the new modules**

From the `nginx -V` output, take the string after `configure arguments:` and append the two `--add-module` options. Run from inside the nginx source directory:

```
./auto/configure \
  <paste the arguments from nginx -V here> \
  --add-module=/usr/local/src/nginx-http2-fingerprint \
  --add-module=/usr/local/src/nginx-ssl-ja3
```

Example if the package had no extra modules (Debian/Ubuntu often adds many):

```
./auto/configure \
  --prefix=/etc/nginx \
  --sbin-path=/usr/sbin/nginx \
  --modules-path=/usr/lib/nginx/modules \
  --with-http_ssl_module \
  --with-http_v2_module \
  --with-stream \
  --with-stream_ssl_preread_module \
  --add-module=/usr/local/src/nginx-http2-fingerprint \
  --add-module=/usr/local/src/nginx-ssl-ja3
```

**5. Build**

```
make -j$(nproc)
```

**6. Replace the binary (backup first)**

```
sudo cp $(which nginx) $(which nginx).bak
sudo cp objs/nginx /usr/sbin/nginx   # path may be /usr/sbin/nginx on Debian/Ubuntu
```

**7. Test and reload**

```
sudo nginx -t && sudo nginx -s reload
```

If anything goes wrong, restore the original binary: `sudo cp /usr/sbin/nginx.bak /usr/sbin/nginx` and reload.

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
        proxy_set_header X-FP-JA3 $ssl_ja3;

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
listen 8440 ssl;
```

(Use a port that is not used by Go, e.g. 8440; 8443/8444 are Go and passthrough.)

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
    }

    include /etc/nginx/streams-available/your.domain.tld;   # optional: e.g. 8444 passthrough
}
```

Do **not** add `proxy_protocol on` to this server — the Go app does not parse PROXY protocol on the TLS listener, and the handshake would break.

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
$ssl_ja3
$http2_fingerprint
$remote_addr
```

These values should be stored in a dataset for later analysis.

---

# HTTP/2 fingerprint: what the module provides

The [nginx-http2-fingerprint](https://github.com/Xetera/nginx-http2-fingerprint) module exposes a single variable `$http2_fingerprint` that already encodes SETTINGS (including INITIAL_WINDOW_SIZE), PRIORITY, and flow-control/window behaviour per Akamai’s method — no separate variables for WINDOW_UPDATE or other frames. Pass it to the Go backend as `X-FP-H2`. The Go server parses this string (format `SETTINGS|WINDOW_UPDATE|PRIORITY|...`) into structured fields (SETTINGS map, initial window, priority) for logging and signals; see [METHODOLOGY.md](METHODOLOGY.md) Phase 2 and Appendix F.

Any future “extended” H2 statistics (e.g. separate variables per frame type) would still be collected via nginx modules rather than Go: there are no mature passive HTTP/2 fingerprinting libraries in Go, and nginx already parses H2 at the edge.

---

# Notes

1. HTTP/2 fingerprint is only available with TLS termination.
2. With TLS passthrough nginx does not see HTTP/2 frames.
3. Fingerprint headers must only be trusted when coming from the trusted proxy.
4. Do not use these headers directly from untrusted (external) traffic.
5. **Real client IP in logs:** Set `X-Forwarded-For` (or `X-Real-IP`) so the Go server logs the real client IP. When the proxy is not on localhost, also set `X-Internal-Proxy "1"` so the backend trusts the forwarded IP (same as for fingerprint headers).
