//! # JSON Web Token (JWT)
//! **Remarks:** Only HS256 as a JWS (signed token) is supported.

const std = @import("std");
const fmt = std.fmt;
const mem = std.mem;
const time = std.time;
const crypto = std.crypto;
const Allocator = mem.Allocator;
const HS256 = crypto.auth.hmac.sha2.HmacSha256;

const Jsonic = @import("jsonic");
const StaticJson = Jsonic.StaticJson;

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
    InvalidSignature
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
            exp: i64,
            /// **Not Before (in seconds)**
            /// - The time before which the token should be considered invalid.
            nbf: i64,
            /// **Issued At (in seconds)**
            /// - The time when the token was issued, checks token freshness.
            iat: i64,
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
            const claims_str = try StaticJson.stringify(heap, claims);
            defer heap.free(claims_str);

            const buff = try heap.alloc(u8, utils.encodeSize(claims_str.len));
            defer heap.free(buff);
            try utils.base64UrlEncode(buff, claims_str);

            const data = try fmt.allocPrint(heap, "{s}.{s}", .{header, buff});
            defer heap.free(data);

            var mac: [HS256.mac_length]u8 = undefined;
            HS256.create(&mac, data, key);

            const sig_buff = try heap.alloc(u8, utils.encodeSize(mac.len));
            defer heap.free(sig_buff);
            try utils.base64UrlEncode(sig_buff, &mac);

            return try fmt.allocPrint(heap, "{s}.{s}", .{data, sig_buff});
        }

        /// # Decodes JWT Token
        /// **WARNING:** You must call `Jwt.free()` after use.
        pub fn decode(heap: Allocator, key: Str, token: Str) !Claims {
            if (mem.count(u8, token, ".") != 2) return Error.InvalidFormat;

            var iter = std.mem.splitAny(u8, token, ".");
            const algo = iter.next() orelse return Error.MalformedToken;
            const data = iter.next() orelse return Error.MalformedToken;
            const hash = iter.next() orelse return Error.MalformedToken;

            const payload = try fmt.allocPrint(heap, "{s}.{s}", .{algo, data});
            defer heap.free(payload);

            var mac: [HS256.mac_length]u8 = undefined;
            HS256.create(&mac, payload, key);

            const sig = try heap.alloc(u8, utils.encodeSize(mac.len));
            defer heap.free(sig);
            try utils.base64UrlEncode(sig, &mac);

            // Validates the signature
            if (sig.len != hash.len) return Error.InvalidSignature;
            const order = crypto.timing_safe.compare(u8, sig, hash, .little);
            if (order != .eq) return Error.InvalidSignature;

            const buff = try heap.alloc(u8, try utils.decodeSize(data));
            defer heap.free(buff);
            try utils.base64UrlDecode(buff, data);

            const claims = try StaticJson.parse(Claims, heap, buff);
            errdefer Jsonic.free(heap, claims) catch unreachable;

            const now = time.timestamp();
            checkNotBefore(now, claims.nbf) catch |err| return err;
            checkExpiration(now, claims.exp) catch |err| return err;

            return claims;
        }

        fn checkNotBefore(now: i64, nbf: i64) !void {
            if (now < nbf) return Error.NotValidYet;
        }

        fn checkExpiration(now: i64, exp: i64) !void {
            if (now > exp) return Error.TokenExpired;
        }
    };
}

const Duration = enum { Second, Minute, Hour };

/// # Returns the EPOCH Time Stamp in Seconds
pub fn setTime(dur: Duration, value: u16) i64 {
    const now = time.timestamp();

    return switch (dur) {
        .Second => now + value,
        .Minute => now + (value * 60),
        .Hour => now + (value * 60 * 60)
    };
}

/// # Frees the Allocated Resources
pub fn free(heap: Allocator, claims: anytype) !void {
    try Jsonic.free(heap, claims);
}
