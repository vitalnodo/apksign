//! ASN.1, the key, and the certificate.
//!
//! Everything here is DER underneath, and DER is something std does
//! both halves of: `std.crypto.codecs.asn1` encodes from a Zig type — a
//! struct is a SEQUENCE, declaration order is wire order, `asn1_tag`
//! overrides the tag — and decodes with bounds it actually checks.
//!
//! So the structures below are declared rather than built.  What the
//! type walk cannot express is a `[]const u8`, since there is no one
//! ASN.1 type a byte slice means; the handful of shapes that needs are
//! named first, and everything after them is a plain Zig struct.
//!
//! The three parts, in order: the shapes, then reading a private key
//! and a certificate, then minting both.

const std = @import("std");
const zip = @import("zip.zig");

const asn1 = std.crypto.codecs.asn1;
const Encoder = asn1.der.Encoder;
const Buf = zip.Buf;

pub const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

// ══ The shapes ═══════════════════════════════════════════

pub const Tag = asn1.Tag;
pub const Oid = asn1.Oid;
pub const Element = asn1.Element;

pub const sequence = Tag.init(.sequence, true, .universal);
pub const set = Tag.init(.set, true, .universal);
pub const integer = Tag.init(.integer, false, .universal);
pub const octet_string = Tag.init(.octetstring, false, .universal);
pub const bit_string = Tag.init(.bitstring, false, .universal);
pub const oid_tag = Tag.init(.oid, false, .universal);
pub const printable_string = Tag.init(.string_printable, false, .universal);
pub const utc_time = Tag.init(.utc_time, false, .universal);
/// [0], constructed — how a certificate's version and PKCS#7's
/// certificates and content are wrapped.
pub const context_0 = Tag.init(@fromBackingInt(@intCast(0)), true, .context_specific);
/// [1], constructed — where an EC private key carries its public half.
pub const context_1 = Tag.init(@fromBackingInt(@intCast(1)), true, .context_specific);

/// Object identifiers, spelled the way they are published rather than
/// as the bytes they encode to.
pub const oid = struct {
    pub const signed_data = Oid.fromDotComptime("1.2.840.113549.1.7.2");
    pub const data = Oid.fromDotComptime("1.2.840.113549.1.7.1");
    pub const sha256 = Oid.fromDotComptime("2.16.840.1.101.3.4.2.1");
    pub const ecdsa_with_sha256 = Oid.fromDotComptime("1.2.840.10045.4.3.2");
    pub const ec_public_key = Oid.fromDotComptime("1.2.840.10045.2.1");
    pub const prime256v1 = Oid.fromDotComptime("1.2.840.10045.3.1.7");
};

// ── Writing ───────────────────────────────────────────────
//
//  Structures are declared as Zig types and handed to `encode`, which
//  walks them.  A struct is a SEQUENCE, an integer is an INTEGER, and
//  `asn1_tag` on a type overrides that.  What the walk cannot do is
//  slices — there is no one ASN.1 type a `[]const u8` means — so the
//  three shapes this file needs are spelled out below.

/// Caller owns the returned memory.
pub const encode = asn1.der.encode;

/// Bytes that are already DER, spliced in untouched.  How a field that
/// has to be carried across unchanged — an issuer, a serial, a whole
/// certificate — goes back out.
pub const Raw = struct {
    bytes: []const u8,

    pub fn encodeDer(self: Raw, e: *Encoder) !void {
        try e.prependBytes(self.bytes);
    }
};

/// Bytes inside an OCTET STRING.
pub const OctetString = struct {
    bytes: []const u8,

    pub const asn1_tag = octet_string;

    pub fn encodeDer(self: OctetString, e: *Encoder) !void {
        try e.tagBytes(asn1_tag, self.bytes);
    }
};

/// Text inside a PrintableString — what a certificate's names are
/// written in.
pub const PrintableString = struct {
    bytes: []const u8,

    pub const asn1_tag = printable_string;

    pub fn encodeDer(self: PrintableString, e: *Encoder) !void {
        try e.tagBytes(asn1_tag, self.bytes);
    }
};

/// Bytes inside `[1]`, where an EC private key carries its public half.
pub const Context1 = struct {
    bytes: []const u8,

    pub const asn1_tag = context_1;

    pub fn encodeDer(self: Context1, e: *Encoder) !void {
        try e.tagBytes(asn1_tag, self.bytes);
    }
};

/// A moment, as YYMMDDHHMMSSZ.
///
/// UTCTime does not write the century down, so RFC 5280 only allows it
/// through 2049 and wants GeneralizedTime after.  Rather than carry
/// both, a date that far out is refused — a certificate minted now
/// cannot reach it, and a silent wrong century would be worse than a
/// build that stops.
pub const UtcTime = struct {
    text: [13]u8,

    pub const asn1_tag = utc_time;
    pub const Error = error{TimeOutOfUtcRange};

    pub fn at(seconds: i64) Error!UtcTime {
        if (seconds < 0) return error.TimeOutOfUtcRange;

        const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(seconds) };
        const yd = es.getEpochDay().calculateYearDay();
        if (yd.year >= 2050) return error.TimeOutOfUtcRange;

        const md = yd.calculateMonthDay();
        const ds = es.getDaySeconds();

        var self: UtcTime = .{ .text = undefined };
        var w: std.Io.Writer = .fixed(&self.text);
        w.print("{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z", .{
            @mod(yd.year, 100),
            md.month.numeric(),
            md.day_index + 1,
            ds.getHoursIntoDay(),
            ds.getMinutesIntoHour(),
            ds.getSecondsIntoMinute(),
        }) catch unreachable;

        return self;
    }

    pub fn encodeDer(self: UtcTime, e: *Encoder) !void {
        try e.tagBytes(asn1_tag, &self.text);
    }
};

/// A BIT STRING.  std's own, which counts the unused bits in the last
/// byte — none, for everything here.
pub const BitString = asn1.BitString;

/// Bytes inside `[0]`, the context tag PKCS#7 wraps its certificates
/// and its content in.
pub const Context0 = struct {
    bytes: []const u8,

    pub const asn1_tag = context_0;

    pub fn encodeDer(self: Context0, e: *Encoder) !void {
        try e.tagBytes(asn1_tag, self.bytes);
    }
};

/// An AlgorithmIdentifier naming an algorithm and nothing else.  The
/// parameters are absent rather than NULL, which is what a verifier
/// expects for these two.
pub const AlgorithmId = struct { algorithm: Oid };

/// An AlgorithmIdentifier whose parameter is a named curve.
pub const CurveAlgorithmId = struct { algorithm: Oid, parameters: Oid };

// ── Reading ───────────────────────────────────────────────

pub const ReadError = Element.DecodeError;

pub const Field = struct {
    tag: Tag,
    /// The body alone.
    body: []const u8,
    /// The element entire — what gets copied when a field has to be
    /// carried across unchanged, as issuer and serial are.
    whole: []const u8,

    pub fn is(f: Field, t: Tag) bool {
        return std.meta.eql(f.tag, t);
    }
};

/// A cursor over a DER buffer.
pub const Reader = struct {
    bytes: []const u8,
    pos: u32 = 0,

    pub fn init(bytes: []const u8) Reader {
        return .{ .bytes = bytes };
    }

    /// A reader over the body of an element, for descending into it.
    pub fn into(f: Field) Reader {
        return .{ .bytes = f.body };
    }

    pub fn next(self: *Reader) ReadError!Field {
        const start = self.pos;
        const elem = try Element.decode(self.bytes, start);
        self.pos = elem.slice.end;
        return .{
            .tag = elem.tag,
            .body = elem.slice.view(self.bytes),
            .whole = self.bytes[start..elem.slice.end],
        };
    }
};

// ══ Reading a key and a certificate ══════════════════════

pub const KeyError = error{
    UnexpectedKeyLength,
    MalformedKey,
    UnsupportedKeyAlgorithm,
} || ReadError;

/// AlgorithmIdentifier { OID id-ecPublicKey, OID prime256v1 } — the
/// only one this signs with.
fn expectP256(field: Field) KeyError!void {
    if (!field.is(sequence)) return error.MalformedKey;
    var r = Reader.into(field);

    const algorithm = try r.next();
    const parameters = try r.next();
    if (!algorithm.is(oid_tag) or !parameters.is(oid_tag)) return error.MalformedKey;

    if (!std.mem.eql(u8, algorithm.body, oid.ec_public_key.encoded) or
        !std.mem.eql(u8, parameters.body, oid.prime256v1.encoded))
    {
        return error.UnsupportedKeyAlgorithm;
    }
}

/// ECPrivateKey ::= SEQUENCE { INTEGER 1, OCTET STRING privateKey,
///                             [0] parameters OPTIONAL,
///                             [1] publicKey OPTIONAL }
///
/// `curve_named` says whether something above has already named the
/// curve.  If nothing has, the optional [0] here has to, and has to say
/// P-256: nothing else tells thirty-two bytes from thirty-two bytes.
fn ecPrivateKey(field: Field, curve_named: bool) KeyError![32]u8 {
    if (!field.is(sequence)) return error.MalformedKey;
    var r = Reader.into(field);

    if (!(try r.next()).is(integer)) return error.MalformedKey; // version 1

    const scalar = try r.next();
    if (!scalar.is(octet_string)) return error.MalformedKey;
    if (scalar.body.len != 32) return error.UnexpectedKeyLength;

    if (!curve_named) {
        const params = r.next() catch return error.UnsupportedKeyAlgorithm;
        if (!params.is(context_0)) return error.UnsupportedKeyAlgorithm;

        var p = Reader.into(params);
        const named = try p.next();
        if (!named.is(oid_tag) or !std.mem.eql(u8, named.body, oid.prime256v1.encoded)) {
            return error.UnsupportedKeyAlgorithm;
        }
    }

    var out: [32]u8 = undefined;
    @memcpy(&out, scalar.body);
    return out;
}

/// The scalar, out of either shape a DER private key arrives in.
/// PKCS#8 opens with version 0 and names the curve before wrapping an
/// ECPrivateKey in an OCTET STRING; the older RFC 5915 form — what
/// `openssl genpkey -outform DER` writes unasked — opens with version 1
/// and is that ECPrivateKey already.
///
/// Every tag on the way is checked, because a wrong turn through DER
/// gives not an error but a different thirty-two bytes.
pub fn privateScalar(pk8: []const u8) KeyError![32]u8 {
    var outer = Reader.init(pk8);
    const top = try outer.next();
    if (!top.is(sequence)) return error.MalformedKey;
    var lvl1 = Reader.into(top);

    const version = try lvl1.next();
    if (!version.is(integer) or version.body.len != 1) return error.MalformedKey;

    switch (version.body[0]) {
        0 => {
            try expectP256(try lvl1.next()); // AlgorithmIdentifier
            const wrapped = try lvl1.next();
            if (!wrapped.is(octet_string)) return error.MalformedKey;

            var lvl2 = Reader.into(wrapped);
            return ecPrivateKey(try lvl2.next(), true);
        },
        1 => return ecPrivateKey(top, false),
        else => return error.MalformedKey,
    }
}

pub fn keyPairFromPkcs8(pk8: []const u8) !Ecdsa.KeyPair {
    const scalar = try privateScalar(pk8);
    return Ecdsa.KeyPair.fromSecretKey(try Ecdsa.SecretKey.fromBytes(scalar));
}

/// Issuer and serial, lifted out of the certificate as raw DER.
/// PKCS#7 names the signer by them, and neither has to be understood
/// to be copied.
///
/// std has a full X.509 parser, and it is the wrong tool here: it
/// discards the serial number after reading it, hands back names
/// without their tag and length, and parses validity dates and
/// algorithms that a signer copying two fields has no opinion about
/// and could only be tripped up by.
pub const Signer = struct {
    serial: []const u8,
    issuer: []const u8,
};

pub fn signerFromCert(cert: []const u8) ReadError!Signer {
    var outer = Reader.init(cert);
    var lvl1 = Reader.into(try outer.next()); // SEQUENCE Certificate
    var lvl2 = Reader.into(try lvl1.next()); // SEQUENCE tbsCertificate

    var first = try lvl2.next();
    // [0] EXPLICIT version is optional; when present it comes first
    if (first.is(context_0)) first = try lvl2.next();
    const serial = first; // INTEGER serialNumber
    _ = try lvl2.next(); // SEQUENCE AlgorithmIdentifier
    const issuer = try lvl2.next(); // Name

    return .{ .serial = serial.whole, .issuer = issuer.whole };
}

pub const CertError = error{MalformedCertificate} || KeyError;

/// The public key the certificate carries.  What a device records at
/// install and checks at update is the certificate, so a pair that does
/// not belong together signs well and verifies against nobody.
pub fn certPublicKey(cert: []const u8) CertError!Ecdsa.PublicKey {
    var outer = Reader.init(cert);
    var lvl1 = Reader.into(try outer.next()); // SEQUENCE Certificate
    var lvl2 = Reader.into(try lvl1.next()); // SEQUENCE tbsCertificate

    var first = try lvl2.next();
    if (first.is(context_0)) first = try lvl2.next(); // [0] version, then serial
    _ = try lvl2.next(); // SEQUENCE AlgorithmIdentifier
    _ = try lvl2.next(); // Name issuer
    _ = try lvl2.next(); // SEQUENCE validity
    _ = try lvl2.next(); // Name subject

    const spki = try lvl2.next(); // SEQUENCE SubjectPublicKeyInfo
    if (!spki.is(sequence)) return error.MalformedCertificate;
    var lvl3 = Reader.into(spki);
    try expectP256(try lvl3.next());

    //  A BIT STRING leads with the count of unused bits in its last
    //  byte, which for a SEC1 point is none.
    const key = try lvl3.next();
    if (!key.is(bit_string) or key.body.len < 2 or key.body[0] != 0) {
        return error.MalformedCertificate;
    }
    return Ecdsa.PublicKey.fromSec1(key.body[1..]) catch error.MalformedCertificate;
}

/// The public key as SubjectPublicKeyInfo DER — what scheme v2 carries
/// beside the signature.
///
/// Derived from the private key rather than taken as a fifth input
/// file: for a named curve the structure is fixed, so the only part
/// that varies is the point itself.
///
///     SEQUENCE { SEQUENCE { OID ecPublicKey, OID prime256v1 },
///                BIT STRING { 00, uncompressed point } }
pub const SubjectPublicKeyInfo = struct {
    algorithm: CurveAlgorithmId,
    subject_public_key: BitString,
};

pub fn publicKeyDer(gpa: std.mem.Allocator, kp: Ecdsa.KeyPair) ![]u8 {
    const point = kp.public_key.toUncompressedSec1();
    return encode(gpa, SubjectPublicKeyInfo{
        .algorithm = .{
            .algorithm = oid.ec_public_key,
            .parameters = oid.prime256v1,
        },
        .subject_public_key = .{ .bytes = &point },
    });
}

// ══ Minting them ════════════════════════════════════════

pub const Options = struct {
    /// The name in both the issuer and the subject; they are the same
    /// thing in a self-signed certificate.
    common_name: []const u8 = "debug",
    days: u32 = 3650,
    serial: i64 = 1,
    /// Seconds since the epoch.  An argument rather than a call, so
    /// that what a certificate says is decided in one place.
    now: i64,
};

// ── The structure, as RFC 5280 writes it ──────────────────

const AttributeTypeAndValue = struct { type: Oid, value: PrintableString };

/// RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
const Rdn = struct {
    only: AttributeTypeAndValue,
    pub const asn1_tag = set;
};

/// Name ::= RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
const Name = struct { only: Rdn };

const Validity = struct { not_before: UtcTime, not_after: UtcTime };

const TbsCertificate = struct {
    /// [0] EXPLICIT version — v3, which is 2
    version: Context0,
    serial: i64,
    signature: AlgorithmId,
    issuer: Name,
    validity: Validity,
    subject: Name,
    subject_public_key_info: SubjectPublicKeyInfo,
};

const Certificate = struct {
    /// Signed as it was encoded, so it goes back out exactly as it was
    /// signed rather than being encoded a second time.
    tbs_certificate: Raw,
    signature_algorithm: AlgorithmId,
    signature: BitString,
};

/// 2.5.4.3 commonName
const oid_common_name = Oid.fromDotComptime("2.5.4.3");

pub fn selfSigned(gpa: std.mem.Allocator, kp: Ecdsa.KeyPair, opts: Options) ![]u8 {
    const name: Name = .{ .only = .{ .only = .{
        .type = oid_common_name,
        .value = .{ .bytes = opts.common_name },
    } } };

    const point = kp.public_key.toUncompressedSec1();
    const tbs = try encode(gpa, TbsCertificate{
        .version = .{ .bytes = &.{ 0x02, 0x01, 0x02 } }, // INTEGER 2
        .serial = opts.serial,
        .signature = .{ .algorithm = oid.ecdsa_with_sha256 },
        .issuer = name,
        .validity = .{
            .not_before = try UtcTime.at(opts.now),
            .not_after = try UtcTime.at(opts.now + @as(i64, opts.days) * 24 * 3600),
        },
        .subject = name,
        .subject_public_key_info = .{
            .algorithm = .{
                .algorithm = oid.ec_public_key,
                .parameters = oid.prime256v1,
            },
            .subject_public_key = .{ .bytes = &point },
        },
    });

    const sig = try kp.sign(tbs, null);
    var buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;

    return encode(gpa, Certificate{
        .tbs_certificate = .{ .bytes = tbs },
        .signature_algorithm = .{ .algorithm = oid.ecdsa_with_sha256 },
        .signature = .{ .bytes = sig.toDer(&buf) },
    });
}

// ── The private key ───────────────────────────────────────

/// ECPrivateKey ::= SEQUENCE { version INTEGER 1,
///                             privateKey OCTET STRING,
///                             [1] EXPLICIT publicKey BIT STRING }
///
/// The curve is named in the PKCS#8 wrapper above rather than in the
/// optional [0] here, which is what openssl writes and what everything
/// reading these expects.
const EcPrivateKey = struct {
    version: i32,
    private_key: OctetString,
    public_key: Context1,
};

const PrivateKeyInfo = struct {
    version: i32,
    algorithm: CurveAlgorithmId,
    private_key: OctetString,
};

pub fn privateKeyDer(gpa: std.mem.Allocator, kp: Ecdsa.KeyPair) ![]u8 {
    const point = kp.public_key.toUncompressedSec1();
    const public_key = try encode(gpa, BitString{ .bytes = &point });

    const inner = try encode(gpa, EcPrivateKey{
        .version = 1,
        .private_key = .{ .bytes = &kp.secret_key.toBytes() },
        .public_key = .{ .bytes = public_key },
    });

    return encode(gpa, PrivateKeyInfo{
        .version = 0,
        .algorithm = .{
            .algorithm = oid.ec_public_key,
            .parameters = oid.prime256v1,
        },
        .private_key = .{ .bytes = inner },
    });
}
