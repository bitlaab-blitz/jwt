//! # JSON Web Token (JWT)
//! **Remarks:** Only HS256 as a JWS (signed token) is supported.

const std = @import("std");
const fmt = std.fmt;
const mem = std.mem;
const crypto = std.crypto;
const Allocator = mem.Allocator;
const HS256 = crypto.auth.hmac.sha2.HmacSha256;

const jsonic = @import("jsonic");
const StaticJSON = jsonic.StaticJSON;

const utils = @import("./utils.zig");

/// # Encoded Header String
/// - Base64URL encoded `{"alg": "HS256", "typ": "JWT"}`
const header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";


const Str = []const u8;

const Error = error {
    NotValidYet,
    TokenExpired,
    InvalidFormat,
    MalformedToken,
    InvalidSignature,
    UnsupportedAlgorithm,
    InvalidIssuedAt,
    InvalidIssuer,
    InvalidAudience
};

/// # Verification Options
const VerifyOptions = struct {
    /// - `iss` - Expected issuer
    iss: ?Str = null,
    /// - `aud` - Expected audience
    aud: ?Str = null
};

/// # JSON Web Signature
/// - `T` - Userdata structure (e.g., `Data { role: []const u8 }`).
pub fn Jws(T: type) type {
    return struct {
        pub const Claims = struct {
            /// **Subject**
            /// - The identity the token refers to (e.g., a user ID).
            sub: Str,
            /// **Expiration Time (in seconds)**
            /// - The time after which the token becomes invalid.
            exp: f64,
            /// **Not Before (in seconds)**
            /// - The time before which the token should be considered invalid.
            nbf: f64,
            /// **Issued At (in seconds)**
            /// - The time when the token was issued. Validated on decode:
            ///   a token issued in the future is rejected.
            iat: f64,
            /// **Issuer**
            /// - Identifies who issued the token (e.g., Auth server or URL).
            iss: Str,
            /// **Audience**
            /// - The intended recipient of the token (e.g., App name, API ID).
            aud: Str,
            /// **Userdata**
            /// - Custom claims carrying app-specific data for business logic.
            data: T,
        };

        const Self = @This();

        /// # Encodes JWT Token
        /// **WARNING:** Return value must be freed by the caller.
        pub fn encode(heap: Allocator, key: Str, claims: Claims) !Str {
            const claims_str = try StaticJSON.stringify(heap, claims);
            defer heap.free(claims_str);

            const claims_len = utils.encodeSize(claims_str.len);
            const sig_len = utils.encodeSize(HS256.mac_length);

            // Layout: "<header>.<claims_base64>.<signature_base64>"
            const total = header.len + 1 + claims_len + 1 + sig_len;
            const token = try heap.alloc(u8, total);
            errdefer heap.free(token);

            @memcpy(token[0..header.len], header);
            token[header.len] = '.';

            try utils.base64UrlEncode(token[header.len + 1..][0..claims_len], claims_str);

            // The MAC covers the already-assembled `header.payload` prefix
            const data = token[0 .. header.len + 1 + claims_len];
            var mac: [HS256.mac_length]u8 = undefined;
            HS256.create(&mac, data, key);

            token[data.len] = '.';
            try utils.base64UrlEncode(token[data.len + 1..], &mac);

            return token;
        }

        /// # Decodes JWT Token
        /// **WARNING:** Return value must be freed by calling `Jwt.free()`.
        pub fn decode(heap: Allocator, io: std.Io, key: Str, token: Str) !Claims {
            var iter = std.mem.splitScalar(u8, token, '.');
            const algo = iter.next() orelse return Error.InvalidFormat;
            const data = iter.next() orelse return Error.InvalidFormat;
            const hash = iter.next() orelse return Error.InvalidFormat;
            if (iter.next() != null) return Error.InvalidFormat;

            const payload = try fmt.allocPrint(heap, "{s}.{s}", .{algo, data});
            defer heap.free(payload);

            var mac: [HS256.mac_length]u8 = undefined;
            HS256.create(&mac, payload, key);

            // Validates the signature against the recomputed MAC
            if (hash.len != utils.encodeSize(mac.len))
                return Error.InvalidSignature;

            var provided: [HS256.mac_length]u8 = undefined;
            utils.base64UrlDecode(&provided, hash)
            catch return Error.InvalidSignature;

            if (!crypto.timing_safe.eql([HS256.mac_length]u8, mac, provided)) {
                return Error.InvalidSignature;
            }

            // Validates the `alg` header (RFC 8725 #3.1)
            const header_len = utils.decodeSize(algo)
            catch return Error.MalformedToken;

            const header_buff = try heap.alloc(u8, header_len);
            defer heap.free(header_buff);

            utils.base64UrlDecode(header_buff, algo)
            catch return Error.MalformedToken;

            // Fast path: tokens from `encode` always carry this exact header,
            // so the dynamic JSON parse is skipped when it matches.
            if (!mem.eql(u8, header_buff, header)) {
                var header_json = jsonic.DynamicJSON.init(heap, header_buff, .{})
                catch return Error.MalformedToken;
                defer header_json.deinit();

                switch (header_json.data()) {
                    .object => |obj| {
                        const alg = obj.get("alg") orelse return Error.MalformedToken;
                        const alg_name = switch (alg) {
                            .string => |s| s,
                            else => return Error.MalformedToken
                        };
                        if (!mem.eql(u8, alg_name, "HS256")) return Error.UnsupportedAlgorithm;
                    },
                    else => return Error.MalformedToken
                }
            }

            const buff = try heap.alloc(u8, utils.decodeSize(data)
            catch return Error.MalformedToken);
            defer heap.free(buff);

            utils.base64UrlDecode(buff, data) catch return Error.MalformedToken;

            const claims = try StaticJSON.parse(Claims, heap, buff);
            errdefer jsonic.free(heap, claims);

            const now = nowSeconds(io);

            checkNotBefore(now, claims.nbf) catch |err| return err;
            checkIssuedAt(now, claims.iat) catch |err| return err;
            checkExpiration(now, claims.exp) catch |err| return err;

            return claims;
        }

        /// # Decodes JWT Token and Enforces Claims
        /// - `opts.iss` - Expected issuer (e.g., Auth server or URL).
        /// - `opts.aud` - Expected audience (e.g., App name, API ID).
        ///
        /// **WARNING:** Return value must be freed by calling `Jwt.free()`.
        pub fn verify(
            heap: Allocator,
            io: std.Io,
            key: Str,
            token: Str,
            opts: VerifyOptions
        ) !Claims {
            const claims = try decode(heap, io, key, token);
            errdefer jsonic.free(heap, claims);

            if (opts.iss) |iss| {
                if (!mem.eql(u8, claims.iss, iss)) return Error.InvalidIssuer;
            }
            if (opts.aud) |aud| {
                if (!mem.eql(u8, claims.aud, aud)) return Error.InvalidAudience;
            }

            return claims;
        }

        fn checkNotBefore(now: f64, nbf: f64) !void {
            if (now < nbf) return Error.NotValidYet;
        }

        fn checkIssuedAt(now: f64, iat: f64) !void {
            if (now < iat) return Error.InvalidIssuedAt;
        }

        fn checkExpiration(now: f64, exp: f64) !void {
            if (now > exp) return Error.TokenExpired;
        }
    };
}

const Duration = enum { Second, Minute, Hour };

/// # Returns the Current EPOCH Time Stamp in Seconds
fn nowSeconds(io: std.Io) f64 {
    return @floatFromInt(std.Io.Clock.real.now(io).toSeconds());
}

/// # Returns the EPOCH Time Stamp in Seconds
pub fn setTime(io: std.Io, dur: Duration, value: u16) f64 {
    const val: f64 = @floatFromInt(value);
    const now = nowSeconds(io);

    return switch (dur) {
        .Second => now + val,
        .Minute => now + (val * 60),
        .Hour => now + (val * 60 * 60)
    };
}

/// # Frees the Allocated Resources
pub fn free(heap: Allocator, claims: anytype) void {
    jsonic.free(heap, claims);
}

test "round trip with URL-safe chars in payload" {
    var gpa_mem = std.heap.DebugAllocator(.{}).init;
    defer std.debug.assert(gpa_mem.deinit() == .ok);
    const heap = gpa_mem.allocator();
    const io = std.Io.Threaded.global_single_threaded.io();

    const Data = struct { role: []const u8 };
    const token = try Jws(Data).encode(heap, "secret", .{
        .sub = "~~~~~", // forces '-'/'_' into the base64url payload
        .iss = "example.com",
        .aud = "hydra",
        .data = .{ .role = "admin" },
        .iat = 0,
        .nbf = 0,
        .exp = 9999999999,
    });
    defer heap.free(token);

    // Assert the payload segment itself contains URL-safe characters so the
    // decode path is genuinely exercised (not just the signature segment).
    const dot1 = std.mem.indexOfScalar(u8, token, '.').?;
    const dot2 = std.mem.lastIndexOfScalar(u8, token, '.').?;
    const payload = token[dot1 + 1 .. dot2];
    try std.testing.expect(std.mem.indexOfAny(u8, payload, "-_") != null);

    const claims = try Jws(Data).decode(heap, io, "secret", token);
    defer free(heap, claims);
    try std.testing.expectEqualStrings("~~~~~", claims.sub);
}

test "base64url decode handles URL-safe alphabet" {
    // "\xff\xff\xbb" encodes to "///+" in std base64, i.e. "__-7" in base64url
    const src = "__-7";
    var dest: [3]u8 = undefined;
    try utils.base64UrlDecode(&dest, src);
    try std.testing.expectEqualSlices(u8, &.{ 0xFF, 0xFF, 0xBB }, &dest);
}

test "tampered signature is rejected" {
    var gpa_mem = std.heap.DebugAllocator(.{}).init;
    defer std.debug.assert(gpa_mem.deinit() == .ok);
    const heap = gpa_mem.allocator();
    const io = std.Io.Threaded.global_single_threaded.io();

    const Data = struct { role: []const u8 };
    const token = try Jws(Data).encode(heap, "secret", .{
        .sub = "a", .iss = "i", .aud = "a",
        .data = .{ .role = "admin" },
        .iat = 0, .nbf = 0, .exp = 9999999999,
    });
    defer heap.free(token);

    const bad = try heap.dupe(u8, token);
    defer heap.free(bad);
    bad[bad.len - 1] ^= 1;

    try std.testing.expectError(error.InvalidSignature, Jws(Data).decode(heap, io, "secret", bad));
}

test "expired token is rejected" {
    var gpa_mem = std.heap.DebugAllocator(.{}).init;
    defer std.debug.assert(gpa_mem.deinit() == .ok);
    const heap = gpa_mem.allocator();
    const io = std.Io.Threaded.global_single_threaded.io();

    const Data = struct { role: []const u8 };
    const token = try Jws(Data).encode(heap, "secret", .{
        .sub = "a", .iss = "i", .aud = "a",
        .data = .{ .role = "admin" },
        .iat = 0, .nbf = 0, .exp = 1,
    });
    defer heap.free(token);

    try std.testing.expectError(error.TokenExpired, Jws(Data).decode(heap, io, "secret", token));
}

test "not-yet-valid token is rejected" {
    var gpa_mem = std.heap.DebugAllocator(.{}).init;
    defer std.debug.assert(gpa_mem.deinit() == .ok);
    const heap = gpa_mem.allocator();
    const io = std.Io.Threaded.global_single_threaded.io();

    const Data = struct { role: []const u8 };
    const token = try Jws(Data).encode(heap, "secret", .{
        .sub = "a", .iss = "i", .aud = "a",
        .data = .{ .role = "admin" },
        .iat = 0, .exp = 9999999999,
        .nbf = 9999999999,
    });
    defer heap.free(token);

    try std.testing.expectError(error.NotValidYet, Jws(Data).decode(heap, io, "secret", token));
}

test "structurally invalid tokens are rejected" {
    var gpa_mem = std.heap.DebugAllocator(.{}).init;
    defer std.debug.assert(gpa_mem.deinit() == .ok);
    const heap = gpa_mem.allocator();
    const io = std.Io.Threaded.global_single_threaded.io();

    const Data = struct { role: []const u8 };

    // No '.' separators
    try std.testing.expectError(error.InvalidFormat, Jws(Data).decode(heap, io, "secret", "not-a-token"));
    // Only one '.' separator
    try std.testing.expectError(error.InvalidFormat, Jws(Data).decode(heap, io, "secret", "a.b"));
    // More than two '.' separators
    try std.testing.expectError(error.InvalidFormat, Jws(Data).decode(heap, io, "secret", "a.b.c.d"));
}

test "malformed signature segment is rejected" {
    var gpa_mem = std.heap.DebugAllocator(.{}).init;
    defer std.debug.assert(gpa_mem.deinit() == .ok);
    const heap = gpa_mem.allocator();
    const io = std.Io.Threaded.global_single_threaded.io();

    const Data = struct { role: []const u8 };
    const token = try Jws(Data).encode(heap, "secret", .{
        .sub = "a", .iss = "i", .aud = "a",
        .data = .{ .role = "admin" },
        .iat = 0, .nbf = 0, .exp = 9999999999,
    });
    defer heap.free(token);

    const bad = try heap.dupe(u8, token);
    defer heap.free(bad);
    bad[bad.len - 1] = '!'; // not a Base64URL character

    try std.testing.expectError(error.InvalidSignature, Jws(Data).decode(heap, io, "secret", bad));
}

test "wrong key is rejected" {
    var gpa_mem = std.heap.DebugAllocator(.{}).init;
    defer std.debug.assert(gpa_mem.deinit() == .ok);
    const heap = gpa_mem.allocator();
    const io = std.Io.Threaded.global_single_threaded.io();

    const Data = struct { role: []const u8 };
    const token = try Jws(Data).encode(heap, "secret", .{
        .sub = "a", .iss = "i", .aud = "a",
        .data = .{ .role = "admin" },
        .iat = 0, .nbf = 0, .exp = 9999999999,
    });
    defer heap.free(token);

    try std.testing.expectError(error.InvalidSignature, Jws(Data).decode(heap, io, "other", token));
}

test "non-HS256 alg header is rejected" {
    var gpa_mem = std.heap.DebugAllocator(.{}).init;
    defer std.debug.assert(gpa_mem.deinit() == .ok);
    const heap = gpa_mem.allocator();
    const io = std.Io.Threaded.global_single_threaded.io();

    // Craft a token whose header declares alg "none" but carries a valid HS256 MAC
    const header_json = "{\"alg\":\"none\",\"typ\":\"JWT\"}";
    const claims_json = "{\"sub\":\"a\",\"exp\":9999999999,\"nbf\":0,\"iat\":0,\"iss\":\"i\",\"aud\":\"a\",\"data\":{\"role\":\"admin\"}}";

    const hbuf = try heap.alloc(u8, utils.encodeSize(header_json.len));
    defer heap.free(hbuf);
    try utils.base64UrlEncode(hbuf, header_json);

    const pbuf = try heap.alloc(u8, utils.encodeSize(claims_json.len));
    defer heap.free(pbuf);
    try utils.base64UrlEncode(pbuf, claims_json);

    const data = try fmt.allocPrint(heap, "{s}.{s}", .{ hbuf, pbuf });
    defer heap.free(data);

    var mac: [HS256.mac_length]u8 = undefined;
    HS256.create(&mac, data, "secret");

    const sig = try heap.alloc(u8, utils.encodeSize(mac.len));
    defer heap.free(sig);
    try utils.base64UrlEncode(sig, &mac);

    const token = try fmt.allocPrint(heap, "{s}.{s}", .{data, sig});
    defer heap.free(token);

    const Data = struct { role: []const u8 };
    try std.testing.expectError(error.UnsupportedAlgorithm, Jws(Data).decode(heap, io, "secret", token));
}

test "tampered header is rejected" {
    var gpa_mem = std.heap.DebugAllocator(.{}).init;
    defer std.debug.assert(gpa_mem.deinit() == .ok);
    const heap = gpa_mem.allocator();
    const io = std.Io.Threaded.global_single_threaded.io();

    const Data = struct { role: []const u8 };
    const token = try Jws(Data).encode(heap, "secret", .{
        .sub = "a", .iss = "i", .aud = "a",
        .data = .{ .role = "admin" },
        .iat = 0, .nbf = 0, .exp = 9999999999,
    });
    defer heap.free(token);

    const bad = try heap.dupe(u8, token);
    defer heap.free(bad);
    bad[5] ^= 1; // flip a char inside the header segment

    try std.testing.expectError(error.InvalidSignature, Jws(Data).decode(heap, io, "secret", bad));
}

test "token issued in the future is rejected" {
    var gpa_mem = std.heap.DebugAllocator(.{}).init;
    defer std.debug.assert(gpa_mem.deinit() == .ok);
    const heap = gpa_mem.allocator();
    const io = std.Io.Threaded.global_single_threaded.io();

    const Data = struct { role: []const u8 };
    const token = try Jws(Data).encode(heap, "secret", .{
        .sub = "a", .iss = "i", .aud = "a",
        .data = .{ .role = "admin" },
        .iat = 9999999999, .nbf = 0, .exp = 9999999999,
    });
    defer heap.free(token);

    try std.testing.expectError(error.InvalidIssuedAt, Jws(Data).decode(heap, io, "secret", token));
}

test "verify enforces issuer and audience" {
    var gpa_mem = std.heap.DebugAllocator(.{}).init;
    defer std.debug.assert(gpa_mem.deinit() == .ok);
    const heap = gpa_mem.allocator();
    const io = std.Io.Threaded.global_single_threaded.io();

    const Data = struct { role: []const u8 };
    const token = try Jws(Data).encode(heap, "secret", .{
        .sub = "a", .iss = "example.com", .aud = "hydra",
        .data = .{ .role = "admin" },
        .iat = 0, .nbf = 0, .exp = 9999999999,
    });
    defer heap.free(token);

    try std.testing.expectError(error.InvalidIssuer, Jws(Data).verify(heap, io, "secret", token, .{ .iss = "evil.com" }));
    try std.testing.expectError(error.InvalidAudience, Jws(Data).verify(heap, io, "secret", token, .{ .aud = "other" }));

    const claims = try Jws(Data).verify(heap, io, "secret", token, .{ .iss = "example.com", .aud = "hydra" });
    defer free(heap, claims);
    try std.testing.expectEqualStrings("hydra", claims.aud);
}
