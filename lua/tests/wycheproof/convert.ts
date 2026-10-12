// Converts C2SP/wycheproof testvectors_v1 files (Apache-2.0) into the TSVs
// run.lua reads, one per algorithm. Regenerate from a checkout of the commit
// named in each TSV's header:
//   export WYCHEPROOF_COMMIT=<commit>; W=<wycheproof checkout>/testvectors_v1
//   bun lua/tests/wycheproof/convert.ts ed25519 $W/ed25519_test.json > lua/tests/wycheproof/ed25519.tsv
//   bun lua/tests/wycheproof/convert.ts ecdsa-p256-sha256 $W/ecdsa_secp256r1_sha256_p1363_test.json > lua/tests/wycheproof/ecdsa-p256-sha256.tsv
//   bun lua/tests/wycheproof/convert.ts ecdsa-p384-sha384 $W/ecdsa_secp384r1_sha384_p1363_test.json > lua/tests/wycheproof/ecdsa-p384-sha384.tsv
//   bun lua/tests/wycheproof/convert.ts rsa-v1_5-sha256 $W/rsa_signature_{2048,3072,4096}_sha256_test.json > lua/tests/wycheproof/rsa-v1_5-sha256.tsv
//   bun lua/tests/wycheproof/convert.ts rsa-pss-sha512 $W/rsa_pss_4096_sha512_mgf1_64_test.json $W/rsa_pss_misc_test.json > lua/tests/wycheproof/rsa-pss-sha512.tsv
//
// Output: "#" comments (sources and their sha256), then "key" lines that set
// the public key for the test lines after them, in the key store's encoding
// (lua/wba/keys.lua): "key <type> <hex>"; test lines: "<file>:<tcId> <result>
// <message hex> <signature hex>". The RSA-PSS files hold groups signed with
// other parameters (rsa_pss_misc: every hash, MGF1 hash and salt length);
// RFC 9421 3.3.1 fixes SHA-512, MGF1 with SHA-512 and a 64-byte salt, so a
// signature valid only under other parameters is converted as "invalid".
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const [alg, ...paths] = process.argv.slice(2);
const SHA: Record<string, string> = { ed25519: "", "ecdsa-p256-sha256": "SHA-256", "ecdsa-p384-sha384": "SHA-384",
  "rsa-v1_5-sha256": "SHA-256", "rsa-pss-sha512": "SHA-512" };
if (!(alg in SHA) || paths.length === 0) throw new Error("usage: convert.ts <alg> <wycheproof json>...");
const type = alg === "ed25519" ? "ed25519" : alg.startsWith("ecdsa-p256") ? "ec-p256" : alg.startsWith("ecdsa-p384") ? "ec-p384" : "rsa";
const minimal = (h: string) => h.toLowerCase().replace(/^(00)+(?=..)/, "");

const commit = process.env.WYCHEPROOF_COMMIT ? ` at commit ${process.env.WYCHEPROOF_COMMIT}` : "";
const head: string[] = [`# Wycheproof vectors for ${alg}, C2SP/wycheproof testvectors_v1${commit} (Apache-2.0)`];
const body: string[] = [];
let total = 0;
for (const path of paths) {
  const raw = readFileSync(path);
  const j = JSON.parse(raw.toString("utf8"));
  const file = path.split("/").pop()!.replace(/_test\.json$/, "");
  head.push(`# ${file}_test.json sha256 ${createHash("sha256").update(raw).digest("hex")}; ${j.numberOfTests} tests`);
  for (const g of j.testGroups) {
    if (SHA[alg] && g.sha !== SHA[alg] && alg !== "rsa-pss-sha512") throw new Error(`${file}: group hash ${g.sha}, not ${SHA[alg]}`);
    const pk = g.publicKey;
    const key = type === "ed25519" ? pk.pk.toLowerCase()
      : type === "rsa" ? `${minimal(pk.modulus)}:${minimal(pk.publicExponent)}` : pk.uncompressed.toLowerCase();
    // RFC 9421 3.3.1's parameters, or every signature in the group is invalid for rsa-pss-sha512.
    const profile = alg !== "rsa-pss-sha512" || (g.sha === "SHA-512" && g.mgf === "MGF1" && g.mgfSha === "SHA-512" && g.sLen === 64);
    body.push(`key\t${type}\t${key}`);
    for (const t of g.tests) {
      body.push([`${file}:${t.tcId}`, profile ? t.result : "invalid", t.msg, t.sig].join("\t"));
      total++;
    }
  }
}
head.push(`# ${total} tests` + (alg === "rsa-pss-sha512"
  ? "; signatures valid only under other PSS parameters count as invalid (RFC 9421 3.3.1)" : ""));
head.push("# key <type> <public key, as lua/wba/keys.lua stores it>; then <file:tcId> <result> <message hex> <signature hex>");
process.stdout.write([...head, ...body].join("\n") + "\n");
