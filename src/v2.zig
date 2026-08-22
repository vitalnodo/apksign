//! APK Signature Scheme v2.
//!
//! A digest of the whole archive, a signature over that, and a block
//! wedged in ahead of the central directory:
//!
//!     unsigned:   [ entries ][ central directory ][ EOCD ]
//!     signed:     [ entries ][ block ][ central directory ][ EOCD' ]
//!
//! EOCD' differs only in the offset it records for the central
//! directory, which has moved by exactly the size of the block.
//!
//! Nothing already in the archive is read back, rewritten or moved.

const std = @import("std");
const zip = @import("zip.zig");
const x509 = @import("x509.zig");

const Buf = zip.Buf;

const Sha256 = std.crypto.hash.sha2.Sha256;
const Ecdsa = x509.Ecdsa;

pub const CHUNK = 1024 * 1024;
pub const SIG_ALGO_ECDSA_SHA256: u32 = 0x0201;
pub const BLOCK_ID: u32 = 0x7109871a;
pub const MAGIC = "APK Sig Block 42";

pub const Error = error{AlreadySigned};

pub fn chunkCount(len: usize) usize {
    return (len + CHUNK - 1) / CHUNK;
}

/// Three regions, each cut into chunks of at most a megabyte.  Every
/// chunk is hashed with a $A5 in front of it and its own length; the
/// chunk hashes are then hashed together behind a $5A and their count.
/// The two prefixes are what stop a chunk's hash from being mistaken
/// for the whole.
pub fn digestRegions(gpa: std.mem.Allocator, regions: []const []const u8) ![32]u8 {
    var total: usize = 0;
    for (regions) |r| total += chunkCount(r.len);

    const digests = try gpa.alloc(u8, total * 32);
    defer gpa.free(digests);

    var out: usize = 0;
    for (regions) |r| {
        var off: usize = 0;
        while (off < r.len) {
            const n = @min(CHUNK, r.len - off);
            var h = Sha256.init(.{});
            var hdr: [5]u8 = undefined;
            hdr[0] = 0xa5;
            std.mem.writeInt(u32, hdr[1..5], @intCast(n), .little);
            h.update(&hdr);
            h.update(r[off .. off + n]);
            h.final(digests[out * 32 ..][0..32]);
            out += 1;
            off += n;
        }
    }

    var top = Sha256.init(.{});
    var hdr: [5]u8 = undefined;
    hdr[0] = 0x5a;
    std.mem.writeInt(u32, hdr[1..5], @intCast(total), .little);
    top.update(&hdr);
    top.update(digests);

    var result: [32]u8 = undefined;
    top.final(&result);
    return result;
}

/// Whether a signing block already sits where this one would go.
/// Signing twice is not idempotent: the second block lands behind the
/// first and the result is wrong in a way nothing says until install.
pub fn isSigned(apk: []const u8, z: zip.Zip) bool {
    if (z.cd_offset < MAGIC.len) return false;
    return std.mem.eql(u8, apk[z.cd_offset - MAGIC.len .. z.cd_offset], MAGIC);
}

pub fn sign(
    gpa: std.mem.Allocator,
    apk: []const u8,
    cert: []const u8,
    pubkey: []const u8,
    kp: Ecdsa.KeyPair,
) ![]u8 {
    const z = try zip.find(apk);
    if (isSigned(apk, z)) return error.AlreadySigned;

    // The EOCD is digested as though the central directory still began
    // where the signing block is about to go — which is where it
    // begins now, so the bytes are taken unchanged.
    const body = apk[0..z.cd_offset];
    const cdir = apk[z.cd_offset .. z.cd_offset + z.cd_size];
    const eocd = apk[z.eocd..];

    const digest = try digestRegions(gpa, &.{ body, cdir, eocd });

    var sd = Buf.init(gpa);
    {
        const digests = try sd.beginLen();
        {
            const one = try sd.beginLen();
            try sd.u32le(SIG_ALGO_ECDSA_SHA256);
            try sd.u32le(32);
            try sd.bytes(&digest);
            try sd.endLen(one);
        }
        try sd.endLen(digests);

        const certs = try sd.beginLen();
        {
            const one = try sd.beginLen();
            try sd.bytes(cert);
            try sd.endLen(one);
        }
        try sd.endLen(certs);

        try sd.u32le(0); // no additional attributes
    }
    const signed_data = sd.items();

    const sig = try kp.sign(signed_data, null);
    var der_buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
    const sig_der = sig.toDer(&der_buf);

    var signer = Buf.init(gpa);
    {
        const sd_len = try signer.beginLen();
        try signer.bytes(signed_data);
        try signer.endLen(sd_len);

        const sigs = try signer.beginLen();
        {
            const one = try signer.beginLen();
            try signer.u32le(SIG_ALGO_ECDSA_SHA256);
            try signer.u32le(@intCast(sig_der.len));
            try signer.bytes(sig_der);
            try signer.endLen(one);
        }
        try signer.endLen(sigs);

        const pk_len = try signer.beginLen();
        try signer.bytes(pubkey);
        try signer.endLen(pk_len);
    }

    var payload = Buf.init(gpa);
    {
        const seq = try payload.beginLen();
        const one = try payload.beginLen();
        try payload.bytes(signer.items());
        try payload.endLen(one);
        try payload.endLen(seq);
    }

    //  size, pairs, size again, magic.  The two sizes count everything
    //  after the first of them.
    var block = Buf.init(gpa);
    {
        const block_len: u64 = 8 + 4 + payload.len() + 8 + 16;
        try block.u64le(block_len);
        try block.u64le(4 + payload.len());
        try block.u32le(BLOCK_ID);
        try block.bytes(payload.items());
        try block.u64le(block_len);
        try block.bytes(MAGIC);
    }

    var out = Buf.init(gpa);
    try out.bytes(body);
    try out.bytes(block.items());
    try out.bytes(cdir);

    const tail = out.len();
    // the directory has moved by exactly the block's length
    const moved = try zip.offset32(@as(usize, z.cd_offset) + block.len());
    try out.bytes(eocd);
    std.mem.writeInt(
        u32,
        out.items()[tail + @offsetOf(std.zip.EndRecord, "central_directory_offset") ..][0..4],
        moved,
        .little,
    );

    return out.items();
}
