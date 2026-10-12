# CRS and signed requests: evidence

Captured 2026-10-11T08:38Z by `lua/tests/live/crs-evidence.sh` against the image built from `lua/wba/Dockerfile`:

- nginx version: nginx/1.30.5
- libmodsecurity 3.0.17
- connector ModSecurity-nginx v1.0.4
- CRS 4.30.0
- base image: `owasp/modsecurity-crs:4.30.0-nginx-202610051210@sha256:133267aa811e1a57a23b52ef04b3c30e802bcbe5454588f6d6af1f69f4b2b667`

The backend is a dead port: 502 means the request passed every rule. CRS's outbound threshold is raised so the 502 itself cannot be refused.

## PL1, HTTP/2, case `verified`

Response: **502**

Request, as ModSecurity recorded it:

```http
GET / HTTP/2.0
x-wba-test: verified-h2
user-agent: wba-live-test
accept: */*
signature-agent: agent1="https://agent.example"
signature-input: sig1=("@authority" "signature-agent";key="agent1");created=1791707875;expires=1791708480;keyid="PMj86PWWwv_tgyeECRSTyeIhBVSSHDVHoWVYEy8A5tI";alg="ed25519";tag="web-bot-auth"
signature: sig1=:xaHtwfkmmJmC0t/slux4Ao/P+0vtYzCNEhrNvrDVwmZc5E/y/2ohfGDy7vPkNbFcdlMoeLjwGPj8QZBFsrZeDw==:
host: example.com
```

CRS rules matched (anomaly totals and the outbound 502 rule left out):

```
none
```

## PL4, HTTP/1.1, case `verified`

Response: **502**

Request, as ModSecurity recorded it:

```http
GET / HTTP/1.1
Host: example.com
User-Agent: curl/8.9.1
Accept: */*
X-WBA-Test: verified
Signature-Agent: agent1="https://agent.example"
Signature-Input: sig1=("@authority" "signature-agent";key="agent1");created=1791707882;expires=1791708487;keyid="PMj86PWWwv_tgyeECRSTyeIhBVSSHDVHoWVYEy8A5tI";alg="ed25519";tag="web-bot-auth"
Signature: sig1=:IIVAX3Aemt0QxQwbyD/A1y40g+c9mG++za1ejGZdxxzWgRSaoKQNjp8JMqIFHlmHD4VPAswJRQhhM1LCKLnZDQ==:
```

CRS rules matched (anomaly totals and the outbound 502 rule left out):

```
none
```

## PL4, HTTP/2, case `verified`

Response: **403**

Request, as ModSecurity recorded it:

```http
GET / HTTP/2.0
x-wba-test: verified-h2
user-agent: wba-live-test
accept: */*
signature-agent: agent1="https://agent.example"
signature-input: sig1=("@authority" "signature-agent";key="agent1");created=1791707884;expires=1791708489;keyid="PMj86PWWwv_tgyeECRSTyeIhBVSSHDVHoWVYEy8A5tI";alg="ed25519";tag="web-bot-auth"
signature: sig1=:9h7frzXU4XJ/wjJGT+4pvD/SDCMrqIv5+6wP4M80fsvhtlZnyUD3HrCuzHNFU6fzw9JCzX8vHBKyqnVR6zebDQ==:
host: example.com
```

CRS rules matched (anomaly totals and the outbound 502 rule left out):

```
920274 (PL4) "Invalid character in request headers (outside of very strict set)"
    REQUEST_HEADERS:signature-input=sig1=("@authority" "signature-agent";key="agent1");created=1791707884;expires=1791708489;keyid="PMj86PWWwv_tgyeECRSTyeIhBVSSHDVHoWVYEy8A5tI";alg="ed25519";tag="web-bot-auth"
```
