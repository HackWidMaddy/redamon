# php2shell upload-progress target (CVE-2026-109618 / CVE-2026-109619)

Deliberately vulnerable PHP target for exercising the agent's **exploitation**
phase end-to-end against the session upload-progress heap use-after-free, using
the ingested `php2shell` tradecraft resource as the knowledge source.

- **Image:** `php:8.4.26-apache` (last pre-fix 8.4 build; fixed in 8.4.27).
- **Vulnerable surface:** `ext/session` RFC1867 upload-progress handler. A
  multipart POST carrying a `PHP_SESSION_UPLOAD_PROGRESS` field drives the
  dangling `zval*` counters described in the advisory.
- **Address:** `172.28.0.93:80` on `redamon_pentest-net` (host alias
  `http://127.0.0.1:8088`).

## Why the config is what it is

| Setting | Value | Why the exploit needs it |
|---|---|---|
| `session.upload_progress.enabled` | `1` | the on-switch for the vulnerable code path (upstream default) |
| `memory_limit` | `8M` | the 12 MB OOM field must exceed it to trigger the leak path |
| `post_max_size` / `upload_max_filesize` | `64M` | above the OOM field, so the body is accepted before memory_limit trips |
| `display_errors` | `On` | PoC target profile |
| `session.use_strict_mode` | `0` | lets the exploit drive its own `PHPSESSID` |
| prefork `MaxRequestWorkers` | `1` | one non-recycling worker makes heap grooming deterministic |

## Run

```bash
cd testing/guinea_pigs/php2shell_upload_progress
docker compose up -d --build
curl -s http://127.0.0.1:8088/            # liveness + confirms upload_progress=1
```

Then paste [`PROMPT.txt`](PROMPT.txt) into an agent chat for a project scoped to
`172.28.0.93` (or `127.0.0.1:8088`).

Tear down with `docker compose down`.

## Caveats

- **Offsets are build-specific.** The PoC's stage 3 needs `zif_system` /
  `zval_ptr_dtor` offsets for *this* `libphp.so`. The public `bookworm` profile
  targets this image; if its hardcoded offsets drift, derive them from the
  running container (`nm -D` / `objdump` on the libphp in `php2shell-target`).
  A missed offset fails at stage 3 with no proof, not a crash of the lab.
- **Intentionally vulnerable.** Local/trusted Docker host only; never expose
  port 8088 or `172.28.0.93` to an untrusted network.
