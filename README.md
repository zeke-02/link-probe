# Link probe

Throwaway test for Fount Cloud's runner link (fount-broker `internal/link`). Can two
Tinfoil enclaves run the link's attested handshake through their shims, and hold it open
as long as a job? Delete everything afterwards.

No secret is involved. The only key is each enclave's per-boot `fount-link` key, and only
random echoes cross the link.

## What it tests

`link/`, `frame/` and `attested/` are fount-broker's packages, copied by `./sync.sh` with only the
import path changed. `SOURCE` records the broker commit they came from. The probe's own
code is `main.go`.

A Tinfoil enclave takes only HTTPS through its shim, so the coordinator reaches a runner
with an HTTP upgrade to `fount-link/1` on `/fount-link`, and the link runs inside it.
Nothing local can show whether Tinfoil's shim forwards an upgrade. That question matters
most here.

`POST /run?peer=https://<b>` on instance A runs these steps against instance B:

| Step | Passes when |
|---|---|
| `self` | A's socket answers, its document verifies against `PEER_PIN`, it endorses A's own `fount-link` key, and a wrong nonce fails |
| `link` | The upgrade crosses B's shim and both ends accept each other's documents |
| `public_attestation` | B's document from its public shim (`/.well-known/tinfoil-attestation?nonce=`), for a nonce of A's, verifies and endorses the key B proved over the link. This is how the proxy will learn a coordinator's attested `job-signing` key |
| `echo_16MiB` | 16 MiB echoes intact, written and read at once |
| `wrong_pin` | A pinning `WRONG_PIN` refuses B (`refused: true`) |
| `unattested_dialler` | B refuses a dialler with an unattested document (`peer_refused: true`) |
| `after_idle_90s` | The link survives 90 s with no traffic |
| `hold` | The link stays up past a job's 30-minute timeout, echoing once a minute (`hold=35` by default) |

`GET /status` on B lists the links B served, including the refused ones.

Locally, `PROBE_UNATTESTED=1 LISTEN_ADDR=127.0.0.1:<port> ./link-probe` runs a pair with
unattested ends. That checks only the probe's own logic. There `unattested_dialler`
shows `peer_refused: false`, since both ends are unattested, and `public_attestation`
gets a 404 with no shim in front.

## Running it

Check first that V3 attestation is enabled for the Tinfoil org.

1. Create the public repo `zeke-02/link-probe` and push this code.
2. Run **Build Image** with `v0.0.1`, and make the GHCR package public.
3. Replace `PLACEHOLDER_DIGEST` in `tinfoil-config.yml` with the digest and commit.
4. Run **Tinfoil Release** with `v0.0.1`. Make it the latest release
   (`gh release edit v0.0.1 -R zeke-02/link-probe --latest`), or fresh attestation
   answers 503.
5. Create the pair:

   ```bash
   tinfoil container create lp-a --repo zeke-02/link-probe --tag v0.0.1
   tinfoil container create lp-b --repo zeke-02/link-probe --tag v0.0.1
   tinfoil container list
   ```

6. Run it, using the instance domains:

   ```bash
   curl -s https://$A/self | jq
   curl -s -X POST "https://$A/run?peer=https://$B"
   curl -s https://$A/status | jq    # poll; the hold step takes 35 minutes
   curl -s https://$B/status | jq '.served'
   ```

7. Delete both instances.

## If the upgrade doesn't cross the shim

`link` then fails with "the runner refused the upgrade" and the shim's status. In that
case the transport has to change, not the link. The alternatives, in order:

- Ask Tinfoil to forward `Upgrade` on listed paths.
- Run each job as two streamed HTTP requests, one per direction.
- Use the attested TCP tunnel that `tinfoil forward` uses. That needs an inference API
  key held by the coordinator.

Report the `link` error verbatim either way.
