# Contributing

Thanks for helping. Issues and pull requests are welcome.

## Ground rules

- **Standard library only** at run time (Python 3.10+). Test-only helpers must also be stdlib.
- **The collector stays small and read-only.** `collect.sh` must stay POSIX `sh`, short enough to read before running (the tests cap it at 60 lines), and must never write, install, use the network or read file contents beyond `/etc/os-release`. `hcproof/collect.sh` must be byte-identical to `collect.sh`.
- **Every verdict must be traceable** to the distribution's own data. Don't add heuristics that mark something "fixed" without a distro statement.
- **No real server data in pull requests.** If an inventory helps reproduce a bug, run it through `hc-proof sanitise` first, and check it yourself before attaching it.

## Before you open a pull request

```sh
python3 -m unittest discover -s tests -t .
```

All tests run offline. If you change classification, add a unit test with hand-written OSV records (see `tests/helpers.py`). If an end-to-end count changes, explain why in the pull request and re-check the affected items against the distribution's tracker (see VERIFICATION.md).

For version comparison changes, add vectors to `tests/vectors/dpkg.json` or `tests/vectors/rpm.json`. Each vector must hold in both directions.

## Reporting a wrong verdict

Open an issue with the "Wrong verdict" template. Include the distribution and release, the package and installed version, the CVE, what the report says, and the link to the distribution's tracker page that says otherwise.

## License

By contributing, you agree that your contribution is licensed under the Apache License 2.0 (see LICENSE).
