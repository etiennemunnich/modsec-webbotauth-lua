# Security

This is an alpha. Run it only on test sites, not in production.

## Reporting a problem

Please do not report a security problem in a public issue, discussion or pull request.

Report it privately through GitHub: open this repository's **Security** tab and choose **Report a vulnerability** (https://github.com/etiennemunnich/modsec-webbotauth-lua/security/advisories/new). Only you and the repository's maintainers can see the report. If that button is not shown, open an issue titled "Security: please get in touch" with no details, and a maintainer will contact you privately.

Include:

- what you found and where (file and line, or the request that shows it);
- how to reproduce it;
- what an attacker could do with it.

You will get a reply within a few days. Please keep it private until a fix is released.

## What is worth reporting

For example:

- a signature that verifies when it should not;
- a way to make the WAF refuse good traffic;
- a way to use a lot of CPU or memory with one request;
- a way to make `wba-keysync` fetch from a private network.

Fixes go into the latest alpha only. The limits under [Known limits](lua/wba/README.md#known-limits) are already known (for example, a DNS answer that changes between key sync's two lookups); report one only if you find it is worse than described there.
