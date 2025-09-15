const std = @import("std");

const jwt = @import("jwt");

pub fn main() !void {
    std.debug.print("Code coverage examples\n", .{});

    // Write your code here...

    const Data = struct {
        role: []const u8,
        feature: []const []const u8
    };

    var gpa_mem = std.heap.DebugAllocator(.{}).init;
    defer std.debug.assert(gpa_mem.deinit() == .ok);
    const heap = gpa_mem.allocator();

    const key = "secret";

    const token = try jwt.Jws(Data).encode(heap, key, .{
        .sub = "john",
        .iss = "example.com",
        .aud = "hydra",
        .data = .{
            .role = "admin",
            .feature = &.{"foo", "bar"}
        },
        .iat = jwt.setTime(.Second, 0),
        .nbf = jwt.setTime(.Second, 0),
        .exp = jwt.setTime(.Minute, 2),
    });
    defer heap.free(token);

    std.debug.print("Token: {s}|\nlen: {d}", .{token, token.len});

    const claims = try jwt.Jws(Data).decode(heap, key, token);
    std.debug.print("{any}\n", .{claims});
    try jwt.free(heap, claims);
}
