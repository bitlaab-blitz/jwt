//! # Utility Module

const std = @import("std");
const Base64Encoder = std.base64.Base64Encoder;
const Base64Decoder = std.base64.Base64Decoder;

const char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


const Str = []const u8;

const Error = error { InsufficientBuffer };

/// # Encodes to Base64 String
pub fn base64UrlEncode(dest: []u8, src: Str) !void {
    const base64_url = Base64Encoder.init(char.*, null);
    _ = base64_url.encode(dest, src);

    var i: usize = 0;
    while (i < dest.len) : (i += 1) {
        switch (dest[i]) {
            '+' => dest[i] = '-',
            '/' => dest[i] = '_',
            else => {} // NOP
        }
    }
}

/// # Returns the Calculated Encode Length
pub fn encodeSize(src_len: usize) usize {
    const base64_url = Base64Encoder.init(char.*, null);
    return base64_url.calcSize(src_len);
}

/// # Decodes from Base64 String
pub fn base64UrlDecode(dest: []u8, src: Str) !void {
    const base64_url = Base64Decoder.init(char.*, null);

    var i: usize = 0;
    while (i < dest.len) : (i += 1) {
        switch (dest[i]) {
            '-' => dest[i] = '+',
            '_' => dest[i] = '/',
            else => {} // NOP
        }
    }

    _ = try base64_url.decode(dest, src);
}

/// # Returns the Calculated Decode Length
pub fn decodeSize(src: Str) !usize {
    const base64_url = Base64Decoder.init(char.*, null);
    return try base64_url.calcSizeForSlice(src);
}
