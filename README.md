# apksign

Signs an APK with **JAR (v1)** and **APK Signature Scheme v2**, and mints the
key and certificate to do it with — no Java, no Android SDK, no OpenSSL. Zig and
its standard library, nothing else.

```sh
zig build
zig-out/bin/apksign keygen -k key.pk8 -c cert.der
zig-out/bin/apksign sign -i unsigned.apk -o signed.apk -k key.pk8 -c cert.der
```

## Read this first

**This is a study of what an APK signature minimally is, not a signing tool to
trust a release to.** It answers "how little does it take before Android will
install this?" — which is not the question a good signer answers.

It was written with substantial help from **Claude Opus 5** and has had no
security review. Do not assume it is safe.

It does work: `apksigner verify` accepts what it produces under both schemes,
signed APKs install and run on an Android 13 device, and the platform refuses to
update one with a different key — which is the property the whole thing is for.

For anything you would mind losing, use the SDK's `apksigner` instead.

## Which scheme, and which Android

| scheme | verified by | here |
| --- | --- | --- |
| v1 (JAR) | every Android there has been — and all a device below **7.0** (API 24) knows | yes |
| v2 | **Android 7.0** (API 24) and later | yes |
| v3 | **Android 9** (API 28) — key rotation | no |
| v3.1 | **Android 13** (API 33) — rotation, revised | no |
| v4 | **Android 11** (API 30) — a sidecar `.idsig` | no |

So `--scheme` is a real choice both ways: an app with `targetSdkVersion` 30 or
higher will not install with a v1 signature alone, and a device older than 7.0
has never heard of v2. `v1+v2` covers both and is the default.

The schemes sit side by side and a device uses the newest it knows, so v3 and v4
could be added without changing what is here — v3 is another ID-value pair in
the same block, v4 a separate file.

Signing with both means `CERT.SF` carries `X-Android-APK-Signed: 2`: without it
the v2 block can be cut back off and an old verifier accepts what is left,
having no way to know a stronger signature was ever there.

## Usage

```
sign
  -i, --in <apk>       the archive to sign
  -o, --out <apk>      where to write the signed one
  -k, --key <pk8>      PKCS#8 EC private key, DER
  -c, --cert <der>     certificate, DER
  -s, --scheme <s>     v1, v2, or v1+v2   (default v1+v2)

keygen
  -k, --key <pk8>      where to write the private key
  -c, --cert <der>     where to write the self-signed certificate
  -n, --name <cn>      the common name        (default debug)
  -d, --days <n>       how long it is valid   (default 3650)
  -f, --force          overwrite a key that is already there
```

`keygen` mints the key and a self-signed certificate itself, which is what makes
the whole thing self-contained. The key is written `0600` and an existing one is
not replaced without `--force`, since an app can only be updated by the key that
first signed it.

`sign` refuses an archive that is signed already — a second signature would not
re-sign it, it would break it — and checks the certificate carries the public
half of the key, because a mismatched pair signs perfectly well and verifies
against nobody. The public key is derived from the private one rather than being
a fifth input file.

## Why

Reaching for `apksigner` means a JDK and a few hundred megabytes of Android SDK
to append three files and one block.

v2 is simpler than v1 underneath: no `MANIFEST.MF`, no `CERT.SF`, and above all
no PKCS#7. What it wants is a digest of the whole archive, a signature over it,
and a block wedged in ahead of the central directory:

```
unsigned:   [ entries ][ central directory ][ EOCD ]
signed:     [ entries ][ block ][ central directory ][ EOCD' ]
```

`EOCD'` differs only in the offset it records for the central directory, which
has moved by exactly the size of the block.

**v2 never touches an entry.** Not only simpler — from Android 11 the platform
maps `resources.arsc` straight out of the APK and refuses to install one where
that entry is deflated. A signer that rebuilds the archive recompresses it
whatever it went in as, and the failure arrives as a refusal to install with
nothing pointing back at the signer.

## The key is ECDSA P-256

Not RSA, for one reason: Zig's standard library signs with the first and has no
code for the second — `std.crypto.Certificate.rsa` has a public key and a
verifier and nothing that signs. That is what keeps this free of any bignum
arithmetic; everything cryptographic is a call into `std`.

**RSA would be the first thing to add**, since plenty of existing Android keys
are RSA. It means modular exponentiation or a bignum dependency — exactly what
this repository is an argument against, so a real decision rather than an
afternoon.

The certificate `keygen` mints carries **no extensions at all** — no
`basicConstraints`, no `keyUsage`. Android does no path validation on an
app-signing certificate; it records the one it saw at install and insists on the
same one at update, so the seven fields it does carry are all the platform
reads. Nothing stops you bringing your own key instead — any P-256 one in PKCS#8
or RFC 5915 DER is read.

## Layout

```
src/main.zig      the command line: sign and keygen
src/v1.zig        JAR signing — the legacy half
src/v2.zig        the chunked digest and the signing block
src/x509.zig      DER, the private key, and minting a certificate
src/zip.zig       the archive, and the buffer both schemes are built in
```

v2's whole production path is the chunked digest, the block, and one function
out of `zip.zig` — finding the end record. Nearly everything else exists for v1:
the manifest, the signature file, PKCS#7, and the entry reader, inflate path and
entry writer that only it calls. That is what the older scheme costs.

### What comes from std

All of the cryptography: SHA-256, ECDSA, CRC-32, base64, inflate.

ASN.1 too, and not merely its primitives. `std.crypto.codecs.asn1` encodes from
a Zig type — a struct is a SEQUENCE, declaration order is wire order — so PKCS#7
is **declared rather than built**, and the only code is filling the types in:

```zig
const SignerInfo = struct {
    version: i32,
    issuer_and_serial: IssuerAndSerial,
    digest_algorithm: x509.AlgorithmId,
    signature_algorithm: x509.AlgorithmId,
    signature: x509.OctetString,
};
```

What the type walk cannot express is a `[]const u8`, since there is no one ASN.1
type a byte slice means; `src/x509.zig` names the few shapes that needs and is
otherwise all std.

`std.zip` supplies the record layouts, and offsets come from `@offsetOf` on its
structs. One thing had to be written — **a zip writer**, because `std.zip` only
reads. Which is just as well: a general writer would rebuild the archive, and
that is precisely what must not happen here.

## Requirements

**Zig 0.17-dev (master)**, and the reason is ASN.1: declaring DER as a Zig type
instead of assembling it byte by byte is what makes this a small program rather
than a tedious one, and that only works on master. In 0.16.0
`asn1.der.Encoder` does not compile at all — two declarations left behind by the
move to the new writer interface, unnoticed because nothing inside std imports
the module.

The cost of master is that master moves. If this stops compiling, that is the
likeliest reason.

## Checking it

There are no unit tests, which is a decision rather than an omission. What
catches a mistake here is not this code agreeing with itself:

```sh
apksign sign -i fixture/app.unsigned.apk -o out.apk -k key.pk8 -c cert.der

# --min-sdk-version matters: from 24 apksigner does not look at the v1
# signature at all, and a broken one passes silently unless you ask
apksigner verify --verbose --min-sdk-version 21 out.apk
adb install out.apk
```

The `--min-sdk-version` is the whole point of running it: `CERT.SF` needs a
section per entry, a digest of the whole manifest authenticates the manifest but
covers no entry, and nothing on a modern device notices — from Android 7.0 on it
reads v2 and never opens `META-INF/` at all. A v1 signature can be wrong for
years and every install still succeed.

`fixture/app.unsigned.apk` is `hello_jni` out of
[forgedex](https://github.com/vitalnodo/forgedex): 2.5 KB of deflated dex,
manifest and `.so` plus two stored directory entries, which between them reach
every path in here. CI signs it three ways and verifies each.

Signing is deterministic (RFC 6979), so `cmp` against a known-good output
catches any change in behaviour.

## What is not here

Single signer only. No v3, no v4, no key rotation, no zip64, no RSA, and no
verification — this signs, it does not check. The private key is a PKCS#8 file
with no passphrase and there is no keystore. Deflate and store are the only
compression methods it knows.

## Licence

MIT.
