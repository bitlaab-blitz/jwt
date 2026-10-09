//! # Utility Module

const std = @import("std");

const Str = []const u8;

/// # Encodes to Base64 String
pub fn base64UrlEncode(dest: []u8, src: Str) !void {
    _ = std.base64.url_safe_no_pad.Encoder.encode(dest, src);
}

/// # Returns the Calculated Encode Length
pub fn encodeSize(src_len: usize) usize {
    return std.base64.url_safe_no_pad.Encoder.calcSize(src_len);
}

/// # Decodes from Base64 String
pub fn base64UrlDecode(dest: []u8, src: Str) !void {
    _ = try std.base64.url_safe_no_pad.Decoder.decode(dest, src);
}

/// # Returns the Calculated Decode Length
pub fn decodeSize(src: Str) !usize {
    return std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(src);
}
