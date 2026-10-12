--[[
rfc_vectors.lua: published RSA-PSS and ECDSA vectors, copied from the
documents (RFC 8792 line wrapping undone):

  * RFC 9421 B.1.2 test-key-rsa-pss and B.1.3 test-key-ecc-p256 (public halves)
  * RFC 9421 B.2.1, B.2.2, B.2.3 (rsa-pss-sha512) and B.2.4
    (ecdsa-p256-sha256): Signature-Input, Signature, and the component
    values each signature base is built from
  * draft-ietf-webbotauth-httpsig-protocol-00 E.1.1 and E.1.2: rsa-pss-sha512
    requests signed with test-key-rsa-pss

The signatures are non-deterministic (RFC 9421 7.3.5): they can only be
verified, never reproduced. Shared by test_sigbase, test_verify and
test_crypto.
--]]

local base64 = require("wba.base64")

local function b64url(s)
    s = s:gsub("%-", "+"):gsub("_", "/")
    return base64.decode(s .. ("="):rep((4 - #s % 4) % 4))
end

local V = {}

-- RFC 9421 B.1.2 (JWK n, e) and B.1.3 (JWK x, y).
V.RSA_PSS_KEY = { type = "rsa", e = "\1\0\1", n = b64url(
    "r4tmm3r20Wd_PbqvP1s2-QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct-Lh1GH45x28Rw3Ry53mm-oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95An"
    .. "dTrifbIFPNU8PPMO7OyrFAHqgDsznjPFmTOtCEcN2Z1FpWgchwuYLPL-Wokqltd11nqqzi-bJ9cvSKADYdUAAN5WUtzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSy"
    .. "ZYoA485mqcO0GVAdVw9lq4aOT9v6d-nb4bnNkQVklLQ3fVAvJm-xdDOp9LCNCN48V2pnDOkFV6-U9nV5oyc6XI2w") }
V.RSA_PSS_KEYID = "oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA" -- its RFC 7638 thumbprint: the draft's E.1 keyid
V.ECC_P256_KEY = { type = "ec-p256", key = "\4" .. b64url("qIVYZVLCrPZHGHjP17CTW0_-D9Lfw0EkjqF7xB4FivA")
    .. b64url("Mc4nN9LTDOBhfoUeg8Ye9WedFRhnZXZJA12Qp0zZ6F0") }
V.ECC_P256_KEYID = "ydQXMtvbsOsZyFir-Y7A8t7fKEM1gbKPvyFkdpu4fvI"

local DIGEST_REQ = "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"

-- RFC 9421 B.2: label, alg, key, Signature-Input member, Signature value,
-- and each covered component's value (by its serialized identifier).
V.B2 = {
    { name = "RFC 9421 B.2.1", label = "sig-b21", alg = "rsa-pss-sha512", key = V.RSA_PSS_KEY,
      input = 'sig-b21=();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"',
      sig = "d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==",
      values = {} },
    { name = "RFC 9421 B.2.2", label = "sig-b22", alg = "rsa-pss-sha512", key = V.RSA_PSS_KEY,
      input = 'sig-b22=("@authority" "content-digest" "@query-param";name="Pet");created=1618884473;keyid="test-key-rsa-pss";tag="header-example"',
      sig = "LjbtqUbfmvjj5C5kr1Ugj4PmLYvx9wVjZvD9GsTT4F7GrcQEdJzgI9qHxICagShLRiLMlAJjtq6N4CDfKtjvuJyE5qH7KT8UCMkSowOB4+ECxCmT8rtAmj/0PIXxi0A0nxKyB09RNrCQibbUjsLS/2YyFYXEu4TRJQzRw1rLEuEfY17SARYhpTlaqwZVtR8NV7+4UKkjqpcAoFqWFQh62s7Cl+H2fjBSpqfZUJcsIk4N6wiKYd4je2U/lankenQ99PZfB4jY3I5rSV2DSBVkSFsURIjYErOs0tFTQosMTAoxk//0RoKUqiYY8Bh0aaUEb0rQl3/XaVe4bXTugEjHSw==",
      values = { ['"@authority"'] = "example.com", ['"content-digest"'] = DIGEST_REQ, ['"@query-param";name="Pet"'] = "dog" } },
    { name = "RFC 9421 B.2.3", label = "sig-b23", alg = "rsa-pss-sha512", key = V.RSA_PSS_KEY,
      input = 'sig-b23=("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"',
      sig = "bbN8oArOxYoyylQQUU6QYwrTuaxLwjAC9fbY2F6SVWvh0yBiMIRGOnMYwZ/5MR6fb0Kh1rIRASVxFkeGt683+qRpRRU5p2voTp768ZrCUb38K0fUxN0O0iC59DzYx8DFll5GmydPxSmme9v6ULbMFkl+V5B1TP/yPViV7KsLNmvKiLJH1pFkh/aYA2HXXZzNBXmIkoQoLd7YfW91kE9o/CCoC1xMy7JA1ipwvKvfrs65ldmlu9bpG6A9BmzhuzF8Eim5f8ui9eH8LZH896+QIF61ka39VBrohr9iyMUJpvRX2Zbhl5ZJzSRxpJyoEZAFL2FUo5fTIztsDZKEgM4cUA==",
      values = { ['"date"'] = "Tue, 20 Apr 2021 02:07:55 GMT", ['"@method"'] = "POST", ['"@path"'] = "/foo",
                 ['"@query"'] = "?param=Value&Pet=dog", ['"@authority"'] = "example.com",
                 ['"content-type"'] = "application/json", ['"content-digest"'] = DIGEST_REQ, ['"content-length"'] = "18" } },
    { name = "RFC 9421 B.2.4", label = "sig-b24", alg = "ecdsa-p256-sha256", key = V.ECC_P256_KEY,
      input = 'sig-b24=("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"',
      sig = "wNmSUAhwb5LxtOtOpNa6W5xj067m5hFrj0XQ4fvpaCLx0NKocgPquLgyahnzDnDAUy5eCdlYUEkLIj+32oiasw==",
      values = { ['"@status"'] = "200", ['"content-type"'] = "application/json",
                 ['"content-digest"'] = "sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:",
                 ['"content-length"'] = "23" } },
}

-- Draft E.1.1 (dictionary Signature-Agent) and E.1.2 (legacy bare String).
V.E1 = {
    { name = "draft E.1.1",
      agent = 'agent2="https://signature-agent.test"',
      input = 'sig2=("@authority" "signature-agent";key="agent2");created=1735689600;keyid="oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA";alg="rsa-pss-sha512";expires=4889289600;nonce="wcfPQPh7SzkvrIVvhD00vNk9PkxJNY2NVbYl2PVBB4zmUoluSwE7W6bPtF60QA3k8g06FU7PPCD+J58YofY1zg==";tag="web-bot-auth"',
      sig = "sig2=:gHzpLNeHaHIO19NaJH9YMW5dcVSi2s0wOMBr6p18vcofS106sfC4KBIS0/szPlBBd1vIcyQ88B6CTEWIhRAiVrb9zfX0mx1aG12CSGWcYkSirHeyTxhbuJvXd27ed6skWoy4PjXItq38936ivUQjfdIwXh1aX6HxkAC3vRnEdSNfntkLWeEuIQ5BLIOBGE39fSwg27Qjq6OVWYas/9/aFUr3HA34MXWYdp+//cvlEKDp3kRoLOw9ro0AOr6srHrTeEtxon2afcws1aZVSlPdd2fZSEIGmw9HAHLDCEkFTERu1gH2k/zIEqgy7CAYXI9E5slog0cLg/Vc6+f8gih33g==:",
      base = '"@authority": example.com\n"signature-agent";key="agent2": "https://signature-agent.test"\n'
          .. '"@signature-params": ("@authority" "signature-agent";key="agent2");created=1735689600;keyid="oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA";alg="rsa-pss-sha512";expires=4889289600;nonce="wcfPQPh7SzkvrIVvhD00vNk9PkxJNY2NVbYl2PVBB4zmUoluSwE7W6bPtF60QA3k8g06FU7PPCD+J58YofY1zg==";tag="web-bot-auth"' },
    { name = "draft E.1.2",
      agent = '"https://signature-agent.test"',
      input = 'sig2=("@authority" "signature-agent");created=1735689600;keyid="oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA";alg="rsa-pss-sha512";expires=1735693200;nonce="XSHtZVCThSIAksXsH9WBs6AtxtXC0eQGiIcUGSoJstFs8lAWakjhrfwzLhyjtme5iXMZvmFWqDEs6cT3Jf+BbQ==";tag="web-bot-auth"',
      sig = "sig2=:I1QWNzGXdP1a4dSvOHLCVOOanEYHDk+ZsVxM9MLX/p4ko69ghKwR5EOtAD96g7g4GWP7lmpM/jFAf9q8EFRDTPLjUXySwMv4YPgabv2LQihTJG2y8a2m6IGltyruwQNiqSJVUuRaG9+b17CGmAMFZh30X6GXLdQJrCARpeTqPwp2DC+a8haDE/VE5EruqzjA5/2mKwvrkzkSqeW5tOVtFwWRRHIOidquf/8Je6kM9mhgkg4arudLA5SL4wyyYE1jURIgcOl8agrfdJ5Def23DIRtiOLRa8jT9cpTLFAuFHN+mrZA/LH9h0gSIg1cPb+0cMASee5uku1KjWcFer7jWA==:",
      base = '"@authority": example.com\n"signature-agent": "https://signature-agent.test"\n'
          .. '"@signature-params": ("@authority" "signature-agent");created=1735689600;keyid="oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA";alg="rsa-pss-sha512";expires=1735693200;nonce="XSHtZVCThSIAksXsH9WBs6AtxtXC0eQGiIcUGSoJstFs8lAWakjhrfwzLhyjtme5iXMZvmFWqDEs6cT3Jf+BbQ==";tag="web-bot-auth"' },
}
V.E1_DIRECTORY = "https://signature-agent.test/.well-known/http-message-signatures-directory"

--- The signature bytes of a "label=:base64:" Signature member.
function V.sig_bytes(member) return base64.decode(member:match(":(.*):$")) end

return V
