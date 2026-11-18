# PermitCore Godot SDK

Native GDScript add-on for Godot4.7+, source version2.2.0. Full shared PermitCore business
surface: product-scoped validation and nonce-protected activation, device removal, usage
reporting, floating sessions and configured-trust offline activation/grace caches.

This source is a release candidate until the dated release receipt confirms publication.
Godot4.7.2 native tests pass on Windows, Linux and macOS. The Windows editor and interactive
Windows release export are checked; a Linux x86_64 release export starts headlessly. Real
hosted acceptance covers activation, product/feature checks, signed grace/manual proof,
metering, floating sessions, device removal and revocation using owned TEST licenses.
These checks do not certify mobile, Web, console or macOS export targets. The engine and this SDK use MIT licenses.

## Install

Copy `addons/permitcore/` into your project's `res://addons/permitcore/`. No .NET edition,
GDExtension binary, Python runtime or external crypto package is needed by the game.
Import the project in Godot. Enabling the editor plugin is optional; it performs no
automatic network calls and stores no credentials. Use the preload path explicitly:

```gdscript
const PermitClient = preload("res://addons/permitcore/permitcore_client.gd")
var client = PermitClient.new("https://api.permitcore.dev", {
    "trusted_public_keys": ["YOUR_TENANT_SPKI_BASE64_PUBLIC_KEY"],
    "cache_directory": "user://permitcore",
    "timeout_seconds": 10.0,
    "max_retries": 2,
})

func check_license(key: String, product_id: String) -> void:
    var result = await client.validate(key, "1.0.0", product_id)
    if result.is_valid:
        print("License accepted") # Never log the key/token.
        $ExportButton.disabled = not result.has_feature("export")
    else:
        $ExportButton.disabled = true
        $Status.text = result.message
```

The API URL belongs to your vendor's PermitCore instance. The public key is independently
configured vendor trust, not a secret, and must not be read from the cache or an unverified
network response. A key accepted for another product must not unlock yours: pass the product ID.
Never ship an Admin API key, tenant passphrase, private signing key or payment secret.

## Configuration

`PermitCoreClient.new(base_url, options)` accepts:

| Option | Default | Meaning |
|---|---|---|
| `enable_offline_cache` | `true` | Persist original signed proof and allow verified outage fallback. |
| `trusted_public_keys` | `[]` | Array of independently configured tenant P-256 SPKI base64 keys. Empty disables trusted cached authorization. |
| `cache_directory` | `user://permitcore` | Per-project persistent seed and signed-token files. |
| `device_id` | automatic | Explicit installation identity; normalized with trimming/lowercasing. |
| `timeout_seconds` | `10.0` | Positive, finite, per-attempt deadline, independent of game time scale. |
| `max_retries` | `2` | Integer additional attempts,0–5, only for safe network/5xx failures. |
| `tls_ca_file` | system/default trust | Optional PEM CA certificate path for an independently trusted self-hosted CA. Hostname verification remains enabled. |

Invalid configuration populates `configuration_error`; network calls return failure without
sending a request. Local signature primitives remain available for independent diagnostics.
Call async operations with `await` on the Godot SceneTree thread. Each request owns a native
HTTPClient and yields frames; multiple requests do not share mutable transport state.

## Complete operation surface

| Operation | Arguments / result |
|---|---|
| `await validate(key, version="", expected_product_id="")` | `LicenseResult`; no activation seat consumed. |
| `await activate(key, device_id="", device_name="", version="", expected_product_id="")` | `LicenseResult`; fetches a fresh nonce, then sends activation once. |
| `await deactivate(tenant_slug, key, activation_id)` | `bool`; only HTTP204 confirms removal. |
| `await meter(key, event_name, quantity=1, meta=null)` | `bool`; only JSON `recorded:true`; quantities below1 become1. |
| `await checkout(key, device_id="", device_name="")` | `FloatingSession`. |
| `await heartbeat(session_token)` | `FloatingSession`. |
| `await try_checkin(session_token)` | `bool`; only HTTP204 confirms release. |
| `await checkin(session_token)` | Best-effort return; use `try_checkin` for confirmation. |
| `get_hardware_id()` | SHA-256 installation fingerprint using Godot OS identity and a persisted per-project random seed. |
| `verify_offline_token(token, public_key_base64)` | Static `TokenResult`; pure local signature/deadline primitive. |
| `verify_grace_cache_token(token, public_key_base64)` | Static `TokenResult`; pure local grace-proof primitive. |
| `activate_offline(token, device_id="", expected_product_id="")` | `TokenResult`; configured trust/context, persist original token. |
| `validate_offline(device_id="", expected_product_id="")` | `TokenResult`; reverify stored original proof every time. |
| `await verify_offline_online(token)` | `TokenResult`; server verification/revocation check, no offline fallback. |
| `result.has_feature(name)` | Case-insensitive feature membership. |

`LicenseResult` exposes `is_valid`, `is_offline`, product identity, remaining activations,
expiry/maintenance, message/error code, features/custom fields, trial/version bounds,
node-lock/grace settings, vendor warning and payment/grace metadata. `data` retains additional
wire fields; it is not a separate authorization source. Failed results cannot retain an
usable `offline_cache_token`. `FloatingSession` exposes `success`, `session_token`,
`expires_at`, `message`, `error_code`; rejected sessions return no token or deadline.
`TokenResult` exposes `is_valid`, `message`, signed `payload` dictionary, `is_revoked` and
server `data` where applicable. Signed payload dictionaries retain their camelCase wire names.

## Transport, offline trust and lifecycle

The native frame-polled HTTPClient never follows redirects. Captured3xx/4xx status stays
authoritative even when the body is truncated. Invalid2xx bodies cannot authorize cached
success. Safe validation, nonce/public-key GET and heartbeat can retry network/5xx failures;
activation POST, checkout, checkin, metering and device removal are never replayed automatically.
False after a lost mutation response does not prove the server made no change.

Offline verification uses Godot's native mbedTLS-backed Crypto API, ECDSA P-256/SHA-256,
SPKI public keys and P1363-to-DER signature adaptation. The signature covers the original
base64url payload segment. Only signed tokens are stored; no server response or cached key
can establish trust. Every grace read checks key SHA-256, product, device, activation evidence
and signed deadline. Manual proof checks configured trust, product/device and its signed expiry.
Rotation requires shipping updated trusted public keys through your application's trusted release.

Signed proof cannot learn about later revocation while offline. Device removal does not erase
already-issued proof. Enforce server time policy and provide recovery without extending proof
locally. `offline_grace_days` is policy metadata, not permission to rewrite a signed deadline.

Portal OTP/account protection remains server-enforced: device-removal failure may require the
human Portal flow. Floating sessions do not fall back to cached authorization; stop protected
work if renewal fails and await stopping before returning the lease. Metering records usage,
not evidence that an external payment was collected. Test/imported/revoked/expired occupied
device seats participate in account capacity; the account limit does not reset monthly.

## Native tests

```text
python -m pip install -r tests/requirements.txt
python tests/run_tests.py --godot /absolute/path/to/godot
```

Windows uses the official `_console.exe` executable. Tests run the actual Godot engine,
shared signature/HTTP/feature/transport vectors, independently signed context attacks,
loopback HTTP/TLS requests, timeout/retry/non-replay and game-loop responsiveness. Python's
cryptography dependency is test-only. A standalone distribution includes `test-vectors/`;
in the monorepo it resolves `../test-vectors/`. No real credentials or hosted payments are
used by these fixtures. Real hosted/editor/export evidence is a separate release gate.
