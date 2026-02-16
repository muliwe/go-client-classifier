# TLS fingerprint data

This folder is kept in git via `.gitkeep`. The file **ja4db.json** is not committed (see `.gitignore`).

- **ja4db.json** — from [JA4+ Database](https://ja4db.com/) (`GET https://ja4db.com/api/read/`). On first process start, if the file is missing it is downloaded here and then loaded to populate `knownBrowserJA4` and `knownLibraryJA4` (TLS vs User-Agent consistency, Appendix G). If the file exists, it is only read.

Override path with env **JA4DB_PATH** (e.g. for tests or custom location).
