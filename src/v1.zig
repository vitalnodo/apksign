//! JAR signing — scheme v1, and everything that exists only for it.
//!
//! This is the legacy half.  A device from Android 7.0 on verifies
//! scheme v2, which touches no entry and needs none of what is here;
//! anything older knows only this.  What it costs is worth seeing: the
//! manifest, the signature file, the PKCS#7 over them — and, in
//! `zip.zig`, the entry reader, the inflate path and the entry writer,
//! which no other scheme asks for.
//!
//! Three files added under META-INF/: a manifest naming every entry
//! and its digest, a signature file digesting that manifest, and a
//! PKCS#7 SignedData over the signature file.
//!
//! This is the older of the two schemes and the heavier one: the
//! digests are per entry and taken over the *uncompressed* bytes, so
//! every deflated entry has to be inflated to be signed.

const std = @import("std");
const zip = @import("zip.zig");
const x509 = @import("x509.zig");

const Buf = zip.Buf;

const Sha256 = std.crypto.hash.sha2.Sha256;
const Ecdsa = x509.Ecdsa;

pub const Error = error{ AlreadySigned, TooManyEntries };

/// One entry's section of the manifest, as a range into it.
const Section = struct { name: []const u8, start: usize, end: usize };

/// Naming the newer schemes in CERT.SF is what stops them being cut
/// back off.  A verifier that finds a v1 signature and this attribute
/// knows a v2 block was there and refuses the archive it was stripped
/// from, instead of quietly accepting the weaker signature.
const anti_stripping = "X-Android-APK-Signed";

/// A JAR manifest is attribute lines in sections separated by a blank
/// line.  The one rule that catches everybody: no line may run past 72
/// bytes, and what spills over goes on the next line behind a single
/// space.
pub fn attribute(out: *Buf, name: []const u8, value: []const u8) !void {
    var line: std.ArrayList(u8) = .empty;
    defer line.deinit(out.gpa);
    try line.appendSlice(out.gpa, name);
    try line.appendSlice(out.gpa, ": ");
    try line.appendSlice(out.gpa, value);

    var rest: []const u8 = line.items;
    var first = true;
    while (rest.len > 0) {
        const room: usize = if (first) 72 else 71;
        const n = @min(room, rest.len);
        if (!first) try out.bytes(" ");
        try out.bytes(rest[0..n]);
        try out.bytes("\r\n");
        rest = rest[n..];
        first = false;
    }
}

/// The files a v1 signature is made of.  Appending a second set to an
/// archive that has them gives two `META-INF/MANIFEST.MF` entries,
/// which is not a signed APK but a broken one.  Matched without regard
/// to case, as the JAR specification says.
pub fn isSignatureFile(name: []const u8) bool {
    const prefix = "META-INF/";
    if (!std.ascii.startsWithIgnoreCase(name, prefix)) return false;

    const rest = name[prefix.len..];
    // only names directly under META-INF/ count
    if (std.mem.indexOfScalar(u8, rest, '/') != null) return false;
    if (std.ascii.eqlIgnoreCase(rest, "MANIFEST.MF")) return true;

    for ([_][]const u8{ ".SF", ".RSA", ".DSA", ".EC" }) |ext| {
        if (std.ascii.endsWithIgnoreCase(rest, ext)) return true;
    }
    return false;
}

fn b64(gpa: std.mem.Allocator, raw: []const u8) ![]const u8 {
    const enc = std.base64.standard.Encoder;
    const buf = try gpa.alloc(u8, enc.calcSize(raw.len));
    return enc.encode(buf, raw);
}

fn sha256b64(gpa: std.mem.Allocator, data: []const u8) ![]const u8 {
    var digest: [32]u8 = undefined;
    Sha256.hash(data, &digest, .{});
    return b64(gpa, &digest);
}

// ── PKCS#7, as X.690 writes it ────────────────────────────
//
//  Declaration order is wire order and a struct is a SEQUENCE, so
//  these types are the structure rather than a description of it.
//  The three shapes that are not sequences — bytes carried across
//  whole, an OCTET STRING, a [0] — are named in `x509`.

const IssuerAndSerial = struct { issuer: x509.Raw, serial: x509.Raw };

const SignerInfo = struct {
    version: i32,
    issuer_and_serial: IssuerAndSerial,
    digest_algorithm: x509.AlgorithmId,
    signature_algorithm: x509.AlgorithmId,
    signature: x509.OctetString,
};

/// SET OF, each with the one member it ever holds here.
const DigestAlgorithms = struct {
    only: x509.AlgorithmId,
    pub const asn1_tag = x509.set;
};
const SignerInfos = struct {
    only: SignerInfo,
    pub const asn1_tag = x509.set;
};

const ContentType = struct { content_type: x509.Oid };

const SignedData = struct {
    version: i32,
    digest_algorithms: DigestAlgorithms,
    content_info: ContentType,
    /// [0] certificates
    certificates: x509.Context0,
    signer_infos: SignerInfos,
};

const ContentInfo = struct {
    content_type: x509.Oid,
    /// [0] EXPLICIT content
    content: x509.Context0,
};

/// A detached PKCS#7 SignedData over `content`.
///
/// Detached: the content itself is not carried, only its signature,
/// because the verifier already has CERT.SF in the zip.  There are
/// no authenticated attributes either, which is what lets the
/// signature be taken over the content directly.
pub fn pkcs7(
    gpa: std.mem.Allocator,
    content: []const u8,
    cert: []const u8,
    kp: Ecdsa.KeyPair,
) ![]u8 {
    const who = try x509.signerFromCert(cert);

    const sig = try kp.sign(content, null);
    var der_buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
    const sig_der = sig.toDer(&der_buf);

    const signed_data = try x509.encode(gpa, SignedData{
        .version = 1,
        .digest_algorithms = .{ .only = .{ .algorithm = x509.oid.sha256 } },
        .content_info = .{ .content_type = x509.oid.data },
        .certificates = .{ .bytes = cert },
        .signer_infos = .{ .only = .{
            .version = 1,
            .issuer_and_serial = .{
                .issuer = .{ .bytes = who.issuer },
                .serial = .{ .bytes = who.serial },
            },
            .digest_algorithm = .{ .algorithm = x509.oid.sha256 },
            .signature_algorithm = .{ .algorithm = x509.oid.ecdsa_with_sha256 },
            .signature = .{ .bytes = sig_der },
        } },
    });

    return x509.encode(gpa, ContentInfo{
        .content_type = x509.oid.signed_data,
        .content = .{ .bytes = signed_data },
    });
}

/// The archive, with the three META-INF files appended.
///
/// `and_v2` says a v2 signature is going on as well, which CERT.SF has
/// to declare — see `anti_stripping`.
pub fn sign(
    gpa: std.mem.Allocator,
    apk: []const u8,
    z: zip.Zip,
    cert: []const u8,
    kp: Ecdsa.KeyPair,
    and_v2: bool,
) ![]u8 {
    const list = try zip.readEntries(gpa, apk, z);

    // the end record's count is about to be added to and written back
    if (list.len != z.count) return error.MalformedCentralDirectory;
    if (z.count > std.math.maxInt(u16) - 3) return error.TooManyEntries;

    for (list) |e| {
        if (isSignatureFile(e.name)) return error.AlreadySigned;
    }

    // ── MANIFEST.MF ───────────────────────────────────────
    var manifest = Buf.init(gpa);
    try attribute(&manifest, "Manifest-Version", "1.0");
    try attribute(&manifest, "Created-By", "apksign");
    try manifest.bytes("\r\n");
    const main_attrs_len = manifest.len();

    //  Where each entry's section landed, so CERT.SF can digest them
    //  one by one below.  Offsets rather than slices: the manifest is
    //  still growing and may move.
    var sections: std.ArrayList(Section) = .empty;

    for (list) |e| {
        // no bytes to digest, and jarsigner leaves them out
        if (e.isDirectory()) continue;

        const data = try zip.entryBytes(gpa, e);
        const start = manifest.len();
        try attribute(&manifest, "Name", e.name);
        try attribute(&manifest, "SHA-256-Digest", try sha256b64(gpa, data));
        try manifest.bytes("\r\n");
        try sections.append(gpa, .{ .name = e.name, .start = start, .end = manifest.len() });
    }

    // ── CERT.SF ───────────────────────────────────────────
    var sf = Buf.init(gpa);
    try attribute(&sf, "Signature-Version", "1.0");
    try attribute(&sf, "Created-By", "apksign");
    if (and_v2) try attribute(&sf, anti_stripping, "2");
    try attribute(&sf, "SHA-256-Digest-Manifest", try sha256b64(gpa, manifest.items()));
    try attribute(
        &sf,
        "SHA-256-Digest-Manifest-Main-Attributes",
        try sha256b64(gpa, manifest.items()[0..main_attrs_len]),
    );
    try sf.bytes("\r\n");

    //  A section per entry, each digesting that entry's section of the
    //  manifest.  The whole-manifest digest above does not stand in for
    //  these: what an entry is covered by a signature at all is these.
    for (sections.items) |s| {
        try attribute(&sf, "Name", s.name);
        try attribute(&sf, "SHA-256-Digest", try sha256b64(gpa, manifest.items()[s.start..s.end]));
        try sf.bytes("\r\n");
    }

    const cert_ec = try pkcs7(gpa, sf.items(), cert, kp);

    // ── the archive, with three entries more ──────────────
    var out = Buf.init(gpa);
    try out.bytes(apk[0..z.cd_offset]);

    const a1 = try zip.putEntry(&out, "META-INF/MANIFEST.MF", manifest.items());
    const a2 = try zip.putEntry(&out, "META-INF/CERT.SF", sf.items());
    const a3 = try zip.putEntry(&out, "META-INF/CERT.EC", cert_ec);

    const cd_start = try zip.offset32(out.len());
    try out.bytes(apk[z.cd_offset .. z.cd_offset + z.cd_size]);
    try zip.putDirEntry(&out, a1);
    try zip.putDirEntry(&out, a2);
    try zip.putDirEntry(&out, a3);
    const cd_end = try zip.offset32(out.len());

    try zip.putEndRecord(&out, z.count + 3, cd_start, cd_end);
    return out.items();
}
