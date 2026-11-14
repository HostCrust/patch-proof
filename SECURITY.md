# Security policy

## Reporting a vulnerability

Please report security problems privately by email to **hello@hostcrust.com**, with "HostCrust Patch Proof security" in the subject. Please don't open a public issue for them. We will acknowledge your report and keep you informed while we fix it.

Useful details:

- the affected version (`hc-proof --version`) or commit;
- what an attacker controls (collector output, the prebuilt index, an OSV file, a mirror URL) and what they gain;
- steps or a file that reproduces it.

## In scope

- **The collector** (`collect.sh`): anything that makes it write, change or send something, or read more than it says it does.
- **Input parsing:** collector output, a pasted `dpkg -l` / `rpm -qa`, OSV bulk files, and the prebuilt index. All of these are untrusted input.
- **The download path:** the prebuilt index download (checksum checks, redirects, cache handling) and the OSV download.
- **The HTML report:** for example, script injection through a package name, version or label.

## Wrong verdicts

A wrong result is a security problem too. If a report says "fixed" or "fixed by backport" for something your distribution's tracker lists as still affected, please report it. If you're unsure whether it's sensitive, email us; otherwise open an issue with the "Wrong verdict" template.

## What the tool does and doesn't promise

- It reports what the distribution's data says about the installed package versions. It does not assess configuration or exposure, and it does not guarantee a server is safe.
- The SHA-256 check on the prebuilt index detects a corrupted or truncated download. It is not a signature. If you need to trust nothing but OSV.dev, build the index yourself with `hc-proof index build` and use `--index`.
