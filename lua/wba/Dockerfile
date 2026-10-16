# Web Bot Auth plugin on the official CRS nginx image.
# Build from the repository root:
#   finch build -f lua/wba/Dockerfile -t crs-wba .
# Run with the key-store DIRECTORY mounted (not the file: wba-keysync replaces
# the file by atomic rename, which a single-file bind mount would not see).
# Publish 8443 (HTTPS); 8080 serves plain HTTP.
#   finch run -v "$PWD/wba-demo/keys:/etc/modsecurity.d/wba/keys:ro" -p 8443:8443 \
#       -e BACKEND=http://your-app:8080 crs-wba
# README.md, Quick start, runs this end to end with a test bot.

# Base image: ModSecurity 3.0.17, CRS 4.30.0, nginx 1.30.5, Debian OpenSSL
# 3.5.7-1~deb13u3 (OpenSSL's August and September 2026 fixes backported). The
# digest is the multi-arch index; TESTING.md names the build each result was
# measured on. Any other tag can be passed with --build-arg CRS_IMAGE=...; the
# version matrix does that for every stable release of the last 12 months.
ARG CRS_IMAGE=owasp/modsecurity-crs:4.30.0-nginx-202610051210@sha256:133267aa811e1a57a23b52ef04b3c30e802bcbe5454588f6d6af1f69f4b2b667

# Build stage: compilers never reach the runtime image. lua-openssl 0.11.1
# (MIT), pinned by commit; its submodules are pinned by that commit. It links
# the image's own libssl/libcrypto (OpenSSL 3), so OpenSSL patches arrive with
# the base image. OPENSSL_LIBS names only those two: the Makefile's default
# (pkg-config --static) would also link zlib and zstd for no use here.
FROM ${CRS_IMAGE} AS build
USER root
# Everything here is built for Lua 5.3 (lua-openssl, the module path in the
# last stage). Stop if this base image's libmodsecurity runs another Lua:
# require("openssl") would fail and every signed request would read
# unverified/engine-error. (The CRS image chooses its Lua with one build
# variable, lua-version; the official images use 5.3.)
RUN ldd /usr/local/modsecurity/lib/libmodsecurity.so.3 | grep -q 'liblua5\.3' \
 || { echo "lua/wba/Dockerfile: this base image's libmodsecurity is not linked against Lua 5.3 (ldd /usr/local/modsecurity/lib/libmodsecurity.so.3). lua-openssl and the module path here are built for Lua 5.3: change them to the image's Lua first." >&2; exit 1; }
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential liblua5.3-dev libssl-dev git ca-certificates \
 && git clone https://github.com/zhaozg/lua-openssl.git /src/lua-openssl \
 && cd /src/lua-openssl \
 && git checkout bd640c240708c77d7b4193906adf4cef30e09dca \
 && git submodule update --init \
 && make LUA_CFLAGS=-I/usr/include/lua5.3 OPENSSL_LIBS="-lssl -lcrypto"

# Test stage, never part of the runtime image:
#   finch build -f lua/wba/Dockerfile --target test .
# Runs every Lua suite on this image's Lua 5.3 with the openssl.so built
# above (test_crypto and test_sha256 require it here), the Wycheproof vectors
# for every algorithm against it, and the mutants that only crypto.lua's own
# tests can catch.
FROM build AS test
RUN apt-get update && apt-get install -y --no-install-recommends lua5.3 openssl
COPY lua /wba/lua
ENV LUA_CPATH="/src/lua-openssl/?.so;;" WBA_REQUIRE_OPENSSL=1 LUA=lua5.3
RUN cd /wba && for t in base64 structured_fields sf_corpus components sigbase keys sha256 coding replay verify negative_vectors entry log conf crypto; do \
      lua5.3 lua/tests/test_$t.lua > /tmp/out 2>&1 || { cat /tmp/out; exit 1; }; tail -1 /tmp/out; \
    done \
 && lua5.3 lua/tests/wycheproof/run.lua lua/tests/wycheproof/*.tsv \
 && bash lua/tests/mutants.sh --crypto

FROM ${CRS_IMAGE}
USER root
COPY --from=build /src/lua-openssl/openssl.so /usr/local/lib/lua/5.3/openssl.so
COPY lua/wba/modsecurity_entry.lua /etc/modsecurity.d/wba/lua/modsecurity_entry.lua
COPY lua/wba/base64.lua lua/wba/structured_fields.lua lua/wba/components.lua lua/wba/sigbase.lua lua/wba/keys.lua \
     lua/wba/identifier.lua lua/wba/sha256.lua lua/wba/digest.lua lua/wba/algorithms.lua lua/wba/crypto.lua \
     lua/wba/verify.lua /etc/modsecurity.d/wba/lua/wba/
COPY lua/wba/coding.lua lua/wba/replay.lua /etc/modsecurity.d/wba/lua/wba/
COPY lua/wba/wba_log.lua /etc/modsecurity.d/wba/lua/wba_log.lua
COPY lua/wba/web-bot-auth-config.conf /etc/modsecurity.d/owasp-crs/plugins/web-bot-auth-config.conf
COPY lua/wba/wba.conf /etc/modsecurity.d/owasp-crs/plugins/web-bot-auth-before.conf
# Accept-Signature (draft 5.3): recipes.conf's 460 and 461 become 403 and 429
# asking for a signature. Inert unless a rule denies with one of them.
# location_common is included in every server block of this image.
COPY lua/wba/nginx/web-bot-auth-accept-signature.conf /tmp/wba-accept-signature.conf
# /var/lib/wba/replay: replay accounting's directory (web-bot-auth-config.conf),
# writable by the nginx workers (uid 101). Mount a filesystem of its own there,
# writable by uid 101 (a root-owned bind mount is not, and fails closed), so
# filling it cannot fill anything else; sweep it with wba-keysync/sweep.ts.
RUN cat /tmp/wba-accept-signature.conf >> /etc/nginx/templates/includes/location_common.conf.template \
 && rm /tmp/wba-accept-signature.conf \
 && mkdir -p /etc/modsecurity.d/wba/keys /var/lib/wba/replay \
 && chown nginx:nginx /var/lib/wba/replay \
 && chmod 0700 /var/lib/wba/replay
USER nginx
