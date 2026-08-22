//! Signs an APK with JAR (v1) and APK Signature Scheme v2, and makes
//! the key and certificate to do it with — no Java, no Android SDK, no
//! OpenSSL, nothing shelled out to.
//!
//! An app targeting API 30 or later will not install with a v1
//! signature alone; an old enough device knows only v1.  Which of the
//! two to write is therefore a choice, and `--scheme` is it.
//!
//! The key is ECDSA P-256, not RSA, for one reason: Zig's standard
//! library signs with the first and has no code for the second — its
//! `rsa` has a public key and a verifier and nothing that signs.  That
//! is what keeps this free of any bignum arithmetic.
//!
//! This is a study of what an APK signature minimally is, not a
//! signing tool to trust a release to.  See the README.

const std = @import("std");
const zip = @import("zip.zig");
const x509 = @import("x509.zig");
const v1 = @import("v1.zig");
const v2 = @import("v2.zig");

pub const Scheme = enum {
    v1,
    v2,
    @"v1+v2",

    fn writesV1(s: Scheme) bool {
        return s != .v2;
    }
    fn writesV2(s: Scheme) bool {
        return s != .v1;
    }
};

const usage =
    \\usage: apksign sign   -i <unsigned.apk> -o <signed.apk> -k <key.pk8> -c <cert.der>
    \\       apksign keygen -k <key.pk8> -c <cert.der>
    \\
    \\sign
    \\  -i, --in <apk>       the archive to sign
    \\  -o, --out <apk>      where to write the signed one
    \\  -k, --key <pk8>      PKCS#8 EC private key, DER
    \\  -c, --cert <der>     certificate, DER
    \\  -s, --scheme <s>     v1, v2, or v1+v2   (default v1+v2)
    \\
    \\keygen
    \\  -k, --key <pk8>      where to write the private key
    \\  -c, --cert <der>     where to write the self-signed certificate
    \\  -n, --name <cn>      the common name        (default debug)
    \\  -d, --days <n>       how long it is valid   (default 3650)
    \\  -f, --force          overwrite a key that is already there
    \\
    \\  -h, --help
    \\
    \\The public key is derived from the private one, so it is never an
    \\input.  Nothing here shells out to openssl, or to anything else.
    \\
    \\This is a study of what an APK signature minimally is, not a
    \\signing tool to trust a release to.  See the README.
    \\
;

const Command = enum { sign, keygen };

const Options = struct {
    command: Command,
    in: ?[]const u8 = null,
    out: ?[]const u8 = null,
    key: ?[]const u8 = null,
    cert: ?[]const u8 = null,
    scheme: Scheme = .@"v1+v2",
    name: []const u8 = "debug",
    days: u32 = 3650,
    force: bool = false,
};

const ParseError = error{
    MissingCommand,
    MissingValue,
    UnknownOption,
    UnknownScheme,
    MissingOption,
    BadNumber,
};

/// Kept apart from main so that nothing about parsing an argument
/// depends on there being a filesystem.
pub fn parseArgs(argv: []const []const u8) ParseError!Options {
    if (argv.len == 0) return error.MissingCommand;
    const command = std.meta.stringToEnum(Command, argv[0]) orelse return error.MissingCommand;

    var o: Options = .{ .command = command };
    var i: usize = 1;

    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        const eat = struct {
            fn next(a: []const []const u8, at: *usize) ParseError![]const u8 {
                at.* += 1;
                if (at.* >= a.len) return error.MissingValue;
                return a[at.*];
            }
        }.next;

        if (is(arg, "-i", "--in")) {
            o.in = try eat(argv, &i);
        } else if (is(arg, "-o", "--out")) {
            o.out = try eat(argv, &i);
        } else if (is(arg, "-k", "--key")) {
            o.key = try eat(argv, &i);
        } else if (is(arg, "-c", "--cert")) {
            o.cert = try eat(argv, &i);
        } else if (is(arg, "-s", "--scheme")) {
            const text = try eat(argv, &i);
            o.scheme = std.meta.stringToEnum(Scheme, text) orelse return error.UnknownScheme;
        } else if (is(arg, "-n", "--name")) {
            o.name = try eat(argv, &i);
        } else if (is(arg, "-d", "--days")) {
            const text = try eat(argv, &i);
            o.days = std.fmt.parseInt(u32, text, 10) catch return error.BadNumber;
        } else if (is(arg, "-f", "--force")) {
            o.force = true;
        } else {
            return error.UnknownOption;
        }
    }

    //  Both commands need somewhere to put a key and a certificate;
    //  only signing needs an archive at either end.
    if (o.key == null or o.cert == null) return error.MissingOption;
    if (command == .sign and (o.in == null or o.out == null)) return error.MissingOption;
    return o;
}

fn is(arg: []const u8, short: []const u8, long: []const u8) bool {
    return std.mem.eql(u8, arg, short) or std.mem.eql(u8, arg, long);
}

/// What runs this is a build script and not a person, so a failure
/// says what it could not do and leaves the exit status saying so.
fn fail(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("apksign: " ++ fmt ++ "\n", args);
    std.process.exit(1);
}

/// A private key nobody else should be able to read.
const private_file: std.Io.File.Permissions = .fromMode(0o600);

fn readFile(
    io: std.Io,
    gpa: std.mem.Allocator,
    path: []const u8,
    what: []const u8,
) []u8 {
    return std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .unlimited) catch |err|
        fail("cannot read the {s} {s}: {s}", .{ what, path, @errorName(err) });
}

fn writeFile(io: std.Io, path: []const u8, data: []const u8, flags: std.Io.Dir.CreateFileOptions) void {
    std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = data, .flags = flags }) catch |err|
        switch (err) {
            error.PathAlreadyExists => fail(
                "{s} is already there.  An app can only be updated by the key that " ++
                    "first signed it, so overwriting one is not undoable: pass --force " ++
                    "if that is really what you want.",
                .{path},
            ),
            else => fail("cannot write {s}: {s}", .{ path, @errorName(err) }),
        };
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const io = init.io;

    var args: std.ArrayList([]const u8) = .empty;
    var it = std.process.Args.Iterator.init(init.minimal.args);
    _ = it.next(); // the program's own name
    while (it.next()) |a| {
        if (is(a, "-h", "--help")) {
            std.debug.print("{s}", .{usage});
            return;
        }
        try args.append(gpa, a);
    }

    const opts = parseArgs(args.items) catch |err| fail("{s}\n\n{s}", .{ switch (err) {
        error.MissingCommand => "the first argument must be sign or keygen",
        error.MissingValue => "an option is missing its value",
        error.UnknownOption => "unknown option",
        error.UnknownScheme => "scheme must be v1, v2 or v1+v2",
        error.MissingOption => "-k and -c are always required; sign also needs -i and -o",
        error.BadNumber => "--days takes a number",
    }, usage });

    switch (opts.command) {
        .keygen => {
            const kp = x509.Ecdsa.KeyPair.generate(io);
            const now = std.Io.Clock.real.now(io); // nanoseconds since the epoch
            const pk8 = try x509.privateKeyDer(gpa, kp);
            const cert = x509.selfSigned(gpa, kp, .{
                .now = @intCast(@divFloor(now.nanoseconds, std.time.ns_per_s)),
                .common_name = opts.name,
                .days = opts.days,
            }) catch |err| switch (err) {
                error.TimeOutOfUtcRange => fail(
                    "--days {d} runs past 2049, which a UTCTime cannot write down",
                    .{opts.days},
                ),
                else => return err,
            };

            const flags: std.Io.Dir.CreateFileOptions = .{ .exclusive = !opts.force };
            writeFile(io, opts.key.?, pk8, .{
                .exclusive = flags.exclusive,
                .permissions = private_file,
            });
            writeFile(io, opts.cert.?, cert, flags);

            std.debug.print(
                "wrote {s} ({d} bytes) and {s} ({d} bytes), CN={s}, {d} days\n",
                .{ opts.key.?, pk8.len, opts.cert.?, cert.len, opts.name, opts.days },
            );
        },

        .sign => {
            const apk = readFile(io, gpa, opts.in.?, "archive");
            const pk8 = readFile(io, gpa, opts.key.?, "private key");
            const cert = readFile(io, gpa, opts.cert.?, "certificate");

            const kp = x509.keyPairFromPkcs8(pk8) catch |err|
                fail("{s} is not a P-256 private key in DER, either PKCS#8 or RFC 5915: {s}", .{ opts.key.?, @errorName(err) });

            // a mismatched pair signs well and verifies against
            // nobody, and the place that finds out is a device
            const in_cert = x509.certPublicKey(cert) catch |err|
                fail("{s} is not a certificate with a P-256 key in it: {s}", .{ opts.cert.?, @errorName(err) });
            if (!std.mem.eql(u8, &in_cert.toUncompressedSec1(), &kp.public_key.toUncompressedSec1())) {
                fail("{s} does not carry the public half of {s}", .{ opts.cert.?, opts.key.? });
            }

            //  v1 first: it adds entries, and v2 digests the archive
            //  those entries are already in.
            var out = apk;
            if (opts.scheme.writesV1()) {
                const z = zip.find(out) catch |err| failArchive(opts.in.?, err);
                out = v1.sign(gpa, out, z, cert, kp, opts.scheme.writesV2()) catch |err|
                    failArchive(opts.in.?, err);
            }
            if (opts.scheme.writesV2()) {
                const pubkey = try x509.publicKeyDer(gpa, kp);
                out = v2.sign(gpa, out, cert, pubkey, kp) catch |err| failArchive(opts.in.?, err);
            }

            writeFile(io, opts.out.?, out, .{});

            std.debug.print(
                "signed {s}: {d} bytes in, {d} out\n",
                .{ @tagName(opts.scheme), apk.len, out.len },
            );
        },
    }
}

/// What the archive itself turned out to be wrong about — each one a
/// refusal to write a file that would look signed and not be.
fn failArchive(path: []const u8, err: anyerror) noreturn {
    fail("{s}: {s}", .{ path, switch (err) {
        error.NotAZip,
        error.NoEndOfCentralDirectory,
        => "not a zip archive",
        error.TruncatedArchive => "truncated — the central directory runs past the end of the file",
        error.MalformedCentralDirectory => "the central directory does not describe this file",
        error.Zip64Unsupported => "zip64, which this does not read",
        error.ArchiveTooLarge => "too large — a zip offset is 32 bits and this needs more",
        error.UnsupportedCompression => "an entry is compressed with something other than deflate",
        error.CorruptEntry => "an entry does not match the size or CRC-32 the archive records for it",
        error.TooManyEntries => "too many entries to add three more",
        error.AlreadySigned => "already signed.  Sign the unsigned archive: appending a second " ++
            "signature to this one would not re-sign it, it would break it",
        else => @errorName(err),
    } });
}
