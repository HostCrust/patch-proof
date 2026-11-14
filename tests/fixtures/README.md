# Test fixtures

| File | What it is |
|---|---|
| `ubuntu-24.04-vm.txt` | Collector output from a real Ubuntu 24.04 VM, taken once on 14 Nov 2026 and frozen (sanitised with `hc-proof sanitise`). User-space packages were up to date; the kernel was still the 24.04 release kernel 6.8.0-31. It describes no server running today. |
| `debian-12-synthetic.txt` | A hand-written Debian 12 inventory: 16 real bookworm package versions, an older running kernel next to a newer installed one, the reboot flag, one removed kernel, and two third-party builds with synthetic version strings. |
| `osv-subset.json.gz` | Every index row for the packages in the two inventories, cut from the OSV.dev Ubuntu and Debian snapshots of 14 Nov 2026. OSV.dev data, under its sources' terms (see NOTICE). |
| `expected.json` | The result counts the end-to-end tests expect. |

How they were checked against the distributions' trackers: [VERIFICATION.md](../../VERIFICATION.md). How to rebuild them: the docstrings of `tests/subset.py` and `tests/test_e2e.py`.
