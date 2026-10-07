const std = @import("std");

const jwt = @import("jwt");

/// # Userdata
/// - Custom claims carrying app-specific data for business logic.
const Userdata = struct {
    role: []const u8,
    feature: []const []const u8
};

pub fn main() !void {
    std.debug.print("Code coverage examples\n", .{});

    var gpa_mem = std.heap.DebugAllocator(.{}).init;
    defer std.debug.assert(gpa_mem.deinit() == .ok);
    const heap = gpa_mem.allocator();

    const key = "secret";

    // Encode a JWT Token
    const token = try jwt.Jws(Userdata).encode(heap, key, .{
        .sub = "john",
        .iss = "example.com",
        .aud = "hydra",
        .data = .{
            .role = "admin",
            .feature = &.{"foo", "bar"}
        },
        .iat = jwt.setTime(.Second, 0),
        .nbf = jwt.setTime(.Second, 0),
        .exp = jwt.setTime(.Minute, 2)
    });
    defer heap.free(token);

    std.debug.print("Token: {s}\n", .{token});

    // Decode a JWT Token
    const claims = try jwt.Jws(Userdata).decode(heap, key, token);
    defer jwt.free(heap, claims);

    std.debug.print("Decoded: sub={s}, role={s}, features={d}\n", .{
        claims.sub, claims.data.role, claims.data.feature.len
    });

    // Verify with issuer and audience enforcement
    const verified = try jwt.Jws(Userdata).verify(heap, key, token, .{
        .iss = "example.com",
        .aud = "hydra"
    });
    defer jwt.free(heap, verified);

    std.debug.print("Verified: iss={s}, aud={s}\n", .{ verified.iss, verified.aud });

    // A mismatching audience is rejected
    if (jwt.Jws(Userdata).verify(heap, key, token, .{ .aud = "other" })) |_| {
        return error.UnexpectedSuccess;
    } else |err| {
        std.debug.print("verify(aud = \"other\") -> {s}\n", .{@errorName(err)});
    }

    // Tampered tokens are rejected
    const tampered = try heap.dupe(u8, token);
    defer heap.free(tampered);
    tampered[tampered.len - 1] ^= 1;

    if (jwt.Jws(Userdata).decode(heap, key, tampered)) |_| {
        return error.UnexpectedSuccess;
    } else |err| {
        std.debug.print("tampered token -> {s}\n", .{@errorName(err)});
    }

    // Expired tokens are rejected
    const stale = try jwt.Jws(Userdata).encode(heap, key, .{
        .sub = "john",
        .iss = "example.com",
        .aud = "hydra",
        .data = .{
            .role = "admin",
            .feature = &.{"foo", "bar"}
        },
        .iat = jwt.setTime(.Second, 0),
        .nbf = 0,
        .exp = 1
    });
    defer heap.free(stale);

    if (jwt.Jws(Userdata).decode(heap, key, stale)) |_| {
        return error.UnexpectedSuccess;
    } else |err| {
        std.debug.print("expired token -> {s}\n", .{@errorName(err)});
    }

    // Tokens issued in the future are rejected
    const premature = try jwt.Jws(Userdata).encode(heap, key, .{
        .sub = "john",
        .iss = "example.com",
        .aud = "hydra",
        .data = .{
            .role = "admin",
            .feature = &.{"foo", "bar"}
        },
        .iat = 9999999999,
        .nbf = 0,
        .exp = 9999999999
    });
    defer heap.free(premature);

    if (jwt.Jws(Userdata).decode(heap, key, premature)) |_| {
        return error.UnexpectedSuccess;
    } else |err| {
        std.debug.print("future issued token -> {s}\n", .{@errorName(err)});
    }

    // Structurally invalid tokens are rejected
    const garbage = "not-a-jwt-token";

    if (jwt.Jws(Userdata).decode(heap, key, garbage)) |_| {
        return error.UnexpectedSuccess;
    } else |err| {
        std.debug.print("invalid token -> {s}\n", .{@errorName(err)});
    }
}
