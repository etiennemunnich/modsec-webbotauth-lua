# Security

This is an alpha shared with a few testers. Please do not open an issue for a security problem.

Send it privately through the channel you received your invitation by (not a GitHub issue, which other testers can read), and include:

- what you found and where (file and line, or the request that shows it);
- how to reproduce it;
- what an attacker could do with it.

You will get a reply within a few days. Please keep it private until it is fixed.

Things worth reporting include: a signature that verifies when it should not, a way to make the WAF refuse good traffic, a way to use a lot of CPU or memory with one request, and a way to make `wba-keysync` fetch from a private network.
