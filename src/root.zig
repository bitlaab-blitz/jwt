//! # JSON Web Token
//! - See documentation at - https://bitlaab.com/api-doc?pkg=jwt

const std = @import("std");
const jwt = @import("./core/jwt.zig");

pub const Jws = jwt.Jws;
pub const free = jwt.free;
pub const setTime = jwt.setTime;
pub const VerifyOptions = jwt.VerifyOptions;

test {
    _ = jwt;
}
