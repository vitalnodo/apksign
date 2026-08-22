//! The archive: finding the end of one, reading what is in it, and
//! adding to it without disturbing any of that.
//!
//! std's `zip` module supplies the record layouts; it has no writer,
//! and the writing here is the part that has to stay byte-exact
//! anyway.  Offsets come from `@offsetOf` on std's structs rather than
//! being counted out, and every field is read and written
//! little-endian explicitly, which is what the format is regardless of
//! the host.
//!
//! Every length in here comes out of the file being signed, so every
//! one is checked against the buffer before it is used to slice, and
//! what cannot be represented — zip64, an offset past four gigabytes —
//! is refused rather than truncated into something that looks fine.

const std = @import("std");
const zip = std.zip;

const Cd = zip.CentralDirectoryFileHeader;
const Local = zip.LocalFileHeader;
const End = zip.EndRecord;

pub const cd_size = @sizeOf(Cd);
pub const local_size = @sizeOf(Local);
pub const end_size = @sizeOf(End);

/// The value a 32-bit field carries when the real one is in a zip64
/// record instead.
const zip64_sentinel32: u32 = 0xffff_ffff;
const zip64_sentinel16: u16 = 0xffff;

fn get(comptime T: type, bytes: []const u8, comptime S: type, comptime field: []const u8) T {
    return std.mem.readInt(T, bytes[@offsetOf(S, field)..][0..@sizeOf(T)], .little);
}

pub const Error = error{
    NotAZip,
    NoEndOfCentralDirectory,
    TruncatedArchive,
    MalformedCentralDirectory,
    UnsupportedCompression,
    CorruptEntry,
    Zip64Unsupported,
    ArchiveTooLarge,
};

/// Every offset a zip records is a uint32.  Past that the alternative
/// to an error is a truncating cast and a file that is quietly wrong.
pub fn offset32(n: usize) Error!u32 {
    if (n > std.math.maxInt(u32)) return error.ArchiveTooLarge;
    return @intCast(n);
}

// ── The buffer both schemes are assembled in ──────────────

/// A growable byte buffer with the length-prefixing these formats are
/// made of: write a placeholder, fill the block, go back and say how
/// long it turned out to be.
pub const Buf = struct {
    gpa: std.mem.Allocator,
    list: std.ArrayList(u8),

    pub fn init(gpa: std.mem.Allocator) Buf {
        return .{ .gpa = gpa, .list = .empty };
    }

    pub fn items(self: *const Buf) []u8 {
        return self.list.items;
    }

    pub fn len(self: *const Buf) usize {
        return self.list.items.len;
    }

    pub fn bytes(self: *Buf, b: []const u8) !void {
        try self.list.appendSlice(self.gpa, b);
    }

    pub fn u16le(self: *Buf, v: u16) !void {
        var tmp: [2]u8 = undefined;
        std.mem.writeInt(u16, &tmp, v, .little);
        try self.bytes(&tmp);
    }

    pub fn u32le(self: *Buf, v: u32) !void {
        var tmp: [4]u8 = undefined;
        std.mem.writeInt(u32, &tmp, v, .little);
        try self.bytes(&tmp);
    }

    pub fn u64le(self: *Buf, v: u64) !void {
        var tmp: [8]u8 = undefined;
        std.mem.writeInt(u64, &tmp, v, .little);
        try self.bytes(&tmp);
    }

    /// Reserve a uint32 length, to be filled in by endLen.
    pub fn beginLen(self: *Buf) !usize {
        try self.u32le(0);
        return self.list.items.len;
    }

    pub fn endLen(self: *Buf, mark: usize) Error!void {
        const n = try offset32(self.list.items.len - mark);
        std.mem.writeInt(u32, self.list.items[mark - 4 ..][0..4], n, .little);
    }
};

/// Where the end of the archive is, and what it says about the
/// central directory.
///
/// The end record is last, but its length depends on a comment nobody
/// writes, so it is looked for rather than seeked to.
pub const Zip = struct {
    eocd: usize,
    cd_offset: u32,
    cd_size: u32,
    count: u16,
};

pub fn find(apk: []const u8) Error!Zip {
    if (apk.len < end_size) return error.NotAZip;
    if (apk.len > std.math.maxInt(u32)) return error.ArchiveTooLarge;

    var i: usize = apk.len - end_size;
    while (true) : (i -= 1) {
        if (std.mem.eql(u8, apk[i..][0..4], &zip.end_record_sig)) {
            const rec = apk[i..];
            const found: Zip = .{
                .eocd = i,
                .cd_size = get(u32, rec, End, "central_directory_size"),
                .cd_offset = get(u32, rec, End, "central_directory_offset"),
                .count = get(u16, rec, End, "record_count_total"),
            };
            // zip64 parks these at all-ones and puts the real values
            // in a record this does not read
            if (found.cd_offset == zip64_sentinel32 or
                found.cd_size == zip64_sentinel32 or
                found.count == zip64_sentinel16)
            {
                return error.Zip64Unsupported;
            }
            // the directory ends at the record pointing at it, not
            // merely somewhere inside the file
            if (@as(usize, found.cd_offset) + found.cd_size > i) {
                return error.TruncatedArchive;
            }
            return found;
        }
        if (i == 0) return error.NoEndOfCentralDirectory;
    }
}

/// An entry as it sits in the archive: still compressed, if it was.
pub const Entry = struct {
    name: []const u8,
    method: u16,
    comp: []const u8,
    /// what the directory says it becomes when inflated
    size: u32,

    pub fn isStored(e: Entry) bool {
        return e.method == @backingInt(zip.CompressionMethod.store);
    }

    /// Named with a trailing slash.  jarsigner leaves these out of the
    /// manifest, and so does this.
    pub fn isDirectory(e: Entry) bool {
        return e.name.len > 0 and e.name[e.name.len - 1] == '/';
    }
};

/// The names and offsets come from the central directory, which is the
/// only place they can be trusted — and only so far: it arrives in the
/// same untrusted file, so each record is checked to fit.
pub fn readEntries(gpa: std.mem.Allocator, apk: []const u8, z: Zip) ![]Entry {
    var list: std.ArrayList(Entry) = .empty;
    var p: usize = z.cd_offset;
    const end = @as(usize, z.cd_offset) + z.cd_size;

    while (p + cd_size <= end) {
        const rec = apk[p..];
        if (!std.mem.eql(u8, rec[0..4], &zip.central_file_header_sig)) {
            return error.MalformedCentralDirectory;
        }

        const method = get(u16, rec, Cd, "compression_method");
        const comp_size = get(u32, rec, Cd, "compressed_size");
        const size = get(u32, rec, Cd, "uncompressed_size");
        const name_len = get(u16, rec, Cd, "filename_len");
        const extra_len = get(u16, rec, Cd, "extra_len");
        const cmt_len = get(u16, rec, Cd, "comment_len");
        const local = get(u32, rec, Cd, "local_file_header_offset");

        // name, extra and comment follow the fixed part, and all
        // three lengths come out of the file
        const rec_len = cd_size + @as(usize, name_len) + extra_len + cmt_len;
        if (p + rec_len > end) return error.MalformedCentralDirectory;

        if (comp_size == zip64_sentinel32 or
            size == zip64_sentinel32 or
            local == zip64_sentinel32)
        {
            return error.Zip64Unsupported;
        }

        if (@as(usize, local) + local_size > apk.len) return error.TruncatedArchive;

        // the local header repeats the name and may carry a different
        // extra field, so the data offset is worked out from it and
        // not from the directory entry
        const lrec = apk[local..];
        if (!std.mem.eql(u8, lrec[0..4], &zip.local_file_header_sig)) {
            return error.MalformedCentralDirectory;
        }
        const lname = get(u16, lrec, Local, "filename_len");
        const lextra = get(u16, lrec, Local, "extra_len");
        const data = @as(usize, local) + local_size + lname + lextra;
        if (data > apk.len or data + comp_size > apk.len) return error.TruncatedArchive;

        try list.append(gpa, .{
            .name = rec[cd_size..][0..name_len],
            .method = method,
            .comp = apk[data .. data + comp_size],
            .size = size,
        });

        p += rec_len;
    }
    return list.toOwnedSlice(gpa);
}

/// v1 digests each entry's *uncompressed* bytes, so a deflated entry
/// has to be inflated first.
///
/// The directory's uncompressed size is the ceiling on that, so that a
/// kilobyte claiming to inflate to a terabyte does not get to try.
pub fn entryBytes(gpa: std.mem.Allocator, e: Entry) ![]const u8 {
    if (e.isStored()) return e.comp;
    if (e.method != @backingInt(zip.CompressionMethod.deflate)) {
        return error.UnsupportedCompression;
    }

    var in: std.Io.Reader = .fixed(e.comp);
    var window: [1 << 16]u8 = undefined;
    var d: std.compress.flate.Decompress = .init(&in, .raw, &window);
    // reaching the limit counts as exceeding it, so ask for one past
    // what was promised: delivering that many is the lie
    const out = d.reader.allocRemaining(gpa, .limited(@as(usize, e.size) + 1)) catch |err| switch (err) {
        error.StreamTooLong => return error.CorruptEntry,
        else => return err,
    };
    if (out.len != e.size) return error.CorruptEntry;
    return out;
}

// ── Writing ───────────────────────────────────────────────
//
//  The added files go in after everything already there and before
//  the central directory.  Appending rather than prepending is
//  deliberate: nothing that exists has to move, so no offset already
//  recorded needs correcting — and an entry that went in stored keeps
//  the alignment it was given.

pub const Added = struct {
    name: []const u8,
    data: []const u8,
    local: u32,
    crc: u32,
};

/// 1980-01-01 00:00:00, as MS-DOS writes it.  Zero is month and day
/// zero, which readers print as `1980-00-00` or reject.
const dos_time: u16 = 0;
const dos_date: u16 = (1 << 5) | 1;

/// A stored entry, written at the current end of the buffer.
pub fn putEntry(out: *Buf, name: []const u8, data: []const u8) !Added {
    const local = try offset32(out.len());
    const size = try offset32(data.len);
    const crc = std.hash.Crc32.hash(data);

    try out.bytes(&zip.local_file_header_sig);
    try out.u16le(10); // version needed
    try out.u16le(0); // flags
    try out.u16le(@backingInt(zip.CompressionMethod.store));
    try out.u16le(dos_time);
    try out.u16le(dos_date);
    try out.u32le(crc);
    try out.u32le(size);
    try out.u32le(size);
    try out.u16le(@intCast(name.len));
    try out.u16le(0); // no extra
    try out.bytes(name);
    try out.bytes(data);

    return .{ .name = name, .data = data, .local = local, .crc = crc };
}

pub fn putDirEntry(out: *Buf, e: Added) !void {
    const size = try offset32(e.data.len);

    try out.bytes(&zip.central_file_header_sig);
    try out.u16le(20); // version made by
    try out.u16le(10); // version needed
    try out.u16le(0); // flags
    try out.u16le(@backingInt(zip.CompressionMethod.store));
    try out.u16le(dos_time);
    try out.u16le(dos_date);
    try out.u32le(e.crc);
    try out.u32le(size);
    try out.u32le(size);
    try out.u16le(@intCast(e.name.len));
    try out.u16le(0); // extra
    try out.u16le(0); // comment
    try out.u16le(0); // disk
    try out.u16le(0); // internal attrs
    try out.u32le(0); // external attrs
    try out.u32le(e.local);
    try out.bytes(e.name);
}

pub fn putEndRecord(out: *Buf, count: u16, cd_start: u32, cd_end: u32) !void {
    try out.bytes(&zip.end_record_sig);
    try out.u16le(0); // this disk
    try out.u16le(0); // disk the directory starts on
    try out.u16le(count);
    try out.u16le(count);
    try out.u32le(cd_end - cd_start);
    try out.u32le(cd_start);
    try out.u16le(0); // no comment
}
