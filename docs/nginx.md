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

File: `/usr/local/nginx/conf/nginx.conf`

```
worker_processes 1;

events {
    worker_connections 1024;
}

http {

    include       mime.types;
    default_type  application/octet-stream;

    sendfile on;

    log_format fp '$remote_addr $ssl_protocol $ssl_cipher $http2_fingerprint';

    access_log logs/access.log fp;

    server {
        listen 80;
        server_name example.com;
        return 301 https://$host$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name example.com;

        ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

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
}
```

---

# TLS passthrough configuration

Add to nginx.conf:

```
stream {

    upstream go_tls_backend {
        server 127.0.0.1:8443;
    }

    server {
        listen 8444;
        proxy_pass go_tls_backend;
        proxy_protocol on;
    }
}
```

In this mode nginx does not terminate TLS and does not extract HTTP/2 fingerprint.

---

# Running nginx

```
sudo /usr/local/nginx/sbin/nginx
```

Reload:

```
sudo /usr/local/nginx/sbin/nginx -s reload
```

Stop:

```
sudo /usr/local/nginx/sbin/nginx -s stop
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
