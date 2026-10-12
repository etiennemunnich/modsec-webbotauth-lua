# CRS and signed requests: evidence

Captured 2026-10-11T08:36Z by `lua/tests/live/crs-evidence.sh` against the image built from `lua/wba/Dockerfile`:

- nginx version: nginx/1.30.5
- libmodsecurity 3.0.17
- connector ModSecurity-nginx v1.0.4
- CRS 4.30.0
- base image: `owasp/modsecurity-crs:4.30.0-nginx-202610051210@sha256:133267aa811e1a57a23b52ef04b3c30e802bcbe5454588f6d6af1f69f4b2b667`

The backend is a dead port: 502 means the request passed every rule. CRS's outbound threshold is raised so the 502 itself cannot be refused.

## PL1, HTTP/1.1, case `pl-nonce-b64-32`

Response: **403**

Request, as ModSecurity recorded it:

```http
GET / HTTP/1.1
Host: example.com
User-Agent: curl/8.9.1
Accept: */*
X-WBA-Test: pl-nonce-b64-32
Signature-Agent: agent1="https://agent.example"
Signature-Input: sig1=("@authority" "signature-agent";key="agent1");created=1791707808;expires=1791708413;keyid="ROcXEe3bJk2JoPIHwuaVMK1fVGHtqlEsIjoywjT3FOA";alg="ed25519";nonce="lES0TBgeDZ5AQwR/Wxs60JidiCeueX7H2BI98ONHpkY=";tag="web-bot-auth"
Signature: sig1=:vZzlqqb67wLKFlmbXqwzwU4XGD8FDj7HPp3P6PTNQ/iW4TePdV/xlRMZFB92Uiyv1bB9R+nVF3+MPWDpY/hBBg==:
```

CRS rules matched (anomaly totals and the outbound 502 rule left out):

```
941120 (PL1) "XSS Filter - Category 2: Event Handler Vector"
    Matched Data: 8ONHpkY=" found within REQUEST_HEADERS:Signature-Input: sig1=("@authority" "signature-agent";key="agent1");created=1791707808;expires=1791708413;keyid="ROcXEe3bJk2JoPIHwuaVMK1fVGHtqlEsIjoywjT3FOA";alg="ed25519";nonce="lES0TBgeDZ5AQwR/Wxs60JidiCeueX7H2BI98ONHpkY=";tag="web-bot-auth"
```

## PL1, HTTP/1.1, case `pl-digest-b64-32`

Response: **403**

Request, as ModSecurity recorded it:

```http
POST / HTTP/1.1
Host: example.com
User-Agent: curl/8.9.1
Content-Digest: sha-256=:hmsi6PXNOrqyV/Ur95FJQD1JwJVcrTr/OnzWOarQXAM=:
Accept: */*
X-WBA-Test: pl-digest-b64-32
Content-Type: application/json
Signature-Agent: agent1="https://agent.example"
Signature-Input: sig1=("@authority" "content-digest" "signature-agent";key="agent1");created=1791707810;expires=1791708415;keyid="ROcXEe3bJk2JoPIHwuaVMK1fVGHtqlEsIjoywjT3FOA";alg="ed25519";tag="web-bot-auth"
Signature: sig1=:BOYy5c1b8CStCDuxmLiUAWX3Td/H6hHbt12QUp0YtSFvz5JAP4LGZOB2tfxQarYYacsjNL8bjryNs1sL1877Dw==:
Content-Length: 11
```

CRS rules matched (anomaly totals and the outbound 502 rule left out):

```
941120 (PL1) "XSS Filter - Category 2: Event Handler Vector"
    Matched Data: /OnzWOarQXAM=: found within REQUEST_HEADERS:Content-Digest: sha-256=:hmsi6PXNOrqyV/Ur95FJQD1JwJVcrTr/OnzWOarQXAM=:
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
Signature-Input: sig1=("@authority" "signature-agent";key="agent1");created=1791707817;expires=1791708422;keyid="ROcXEe3bJk2JoPIHwuaVMK1fVGHtqlEsIjoywjT3FOA";alg="ed25519";tag="web-bot-auth"
Signature: sig1=:tReopBt/V65KN1J0HRn8yGmxy3T86VTSoN6TgUSLcsXY//KD0XCCaB6cr0+uepCfsOfV8wnmqwqbno6zV+aJDg==:
```

CRS rules matched (anomaly totals and the outbound 502 rule left out):

```
none
```

## PL4, HTTP/2, case `verified`

Response: **502**

Request, as ModSecurity recorded it:

```http
GET / HTTP/2.0
x-wba-test: verified-h2
user-agent: wba-live-test
accept: */*
signature-agent: agent1="https://agent.example"
signature-input: sig1=("@authority" "signature-agent";key="agent1");created=1791707819;expires=1791708424;keyid="ROcXEe3bJk2JoPIHwuaVMK1fVGHtqlEsIjoywjT3FOA";alg="ed25519";tag="web-bot-auth"
signature: sig1=:D7KO54dwtqYItk0R0fMymdHF/rBLSUUlC8OcELw2feHaLcoWpFPz7ELlSH9r/swgvY83eTys9GvJdcKRJOORAA==:
host: example.com
```

CRS rules matched (anomaly totals and the outbound 502 rule left out):

```
none
```

## PL4, HTTP/2, case `agent-jwks`

Response: **502**

Request, as ModSecurity recorded it:

```http
GET / HTTP/2.0
x-wba-test: agent-jwks-h2
user-agent: wba-live-test
accept: */*
signature-agent: agent1="https://jwks.example/keys.json?v=2";type=jwks_uri
signature-input: sig1=("@authority" "signature-agent";key="agent1");created=1791707821;expires=1791708426;keyid="L9YpFAZI4-qujWYA9tx5ln8RCt1yL9ok_mtX0VxPso8";alg="ed25519";tag="web-bot-auth"
signature: sig1=:wxZOB7NkpVa09JJId0H2knGSkszGaSCKo2jtFMRGK8XtkDDiUnfSY1jkWM7NST44Wrg6o1PL6iApLXuHOt37Bw==:
host: example.com
```

CRS rules matched (anomaly totals and the outbound 502 rule left out):

```
none
```
