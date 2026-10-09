# How to use

First, import Jwt on your Zig source file.

```zig
const jwt = @import("jwt");
```

Now, add the following code into your main function.

```zig
pub fn main(init: std.process.Init) !void {
    const heap = init.gpa;
    const io = init.io;
```

## Setting the Time Claims

`setTime` returns an EPOCH timestamp (in seconds) relative to the current
time. It accepts an `Io`, a duration and a value, e.g.
`setTime(io, .Minute, 2)` means "two minutes from now".

| Duration  | Meaning                       |
|-----------|-------------------------------|
| `.Second` | `now + value` seconds         |
| `.Minute` | `now + value * 60` seconds    |
| `.Hour`   | `now + value * 60 * 60` seconds |

## Encode a JWT Token

Here, `Userdata` is a custom struct that holds application-specific authentication details.

```zig
const Userdata = struct {
    role: []const u8,
    feature: []const []const u8
};

const key = "secret";

const token = try jwt.Jws(Userdata).encode(heap, key, .{
    .sub = "john",
    .iss = "example.com",
    .aud = "hydra",
    .data = .{
        .role = "admin",
        .feature = &.{"foo", "bar"}
    },
    .iat = jwt.setTime(io, .Second, 0),
    .nbf = jwt.setTime(io, .Second, 0),
    .exp = jwt.setTime(io, .Minute, 2)
});
defer heap.free(token);

std.debug.print("JWT Token: {s}\n", .{token});
```

The token is always signed with HS256 and the header
`{"alg":"HS256","typ":"JWT"}` is fixed.

## Decode a JWT Token

Token validation is handled internally, which automatically:

- Verifies the signature in constant time against the HS256 MAC.
- Checks the `alg` header is `HS256` (algorithm confusion protection).
- Checks the required claims: `exp` (expiration), `nbf` (not before) and
  `iat` (issued at — a token issued in the future is rejected).
- Ensures the token is structurally valid and not tampered with.

```zig
const token = "your jwt token...";

const claims = try jwt.Jws(Userdata).decode(heap, io, key, token);
std.debug.print("{any}\n", .{claims});
jwt.free(heap, claims);
```

## Verify with Issuer and Audience Enforcement

`decode` does not enforce `iss` and `aud` — per the JWT specification,
checking them is the application's responsibility. Use `verify` when you
want the library to enforce the expected issuer and/or audience for you.

```zig
const claims = try jwt.Jws(Userdata).verify(heap, io, key, token, .{
    .iss = "example.com",
    .aud = "hydra"
});
jwt.free(heap, claims);
```

Both options are optional; pass only what you need:

```zig
// Enforce audience only
const claims = try jwt.Jws(Userdata).verify(heap, io, key, token, .{
    .aud = "hydra"
});
jwt.free(heap, claims);
```

## Error Handling

Decode and verify return a rich error set. Handle them with a `catch` or
an `if ... else |err|` block, and use `@errorName` to inspect.

| Error                 | Raised when                                            |
|-----------------------|--------------------------------------------------------|
| `InvalidFormat`       | Token is not a `header.payload.signature` triple       |
| `MalformedToken`      | Segments are not valid Base64URL / the header is not a JSON object with an `alg` claim |
| `InvalidSignature`    | Signature verification failed or the key is wrong      |
| `UnsupportedAlgorithm`| Header declares an `alg` other than `HS256`            |
| `NotValidYet`         | `now < nbf`                                            |
| `TokenExpired`        | `now > exp`                                            |
| `InvalidIssuedAt`     | `now < iat` (token issued in the future)               |
| `InvalidIssuer`       | `iss` does not match the expected issuer (verify only) |
| `InvalidAudience`     | `aud` does not match the expected audience (verify only) |

```zig
if (jwt.Jws(Userdata).decode(heap, io, key, token)) |claims| {
    defer jwt.free(heap, claims);
    // ... authenticated
} else |err| switch (err) {
    error.TokenExpired => std.debug.print("please log in again\n", .{}),
    error.InvalidSignature => std.debug.print("token was tampered with\n", .{}),
    else => std.debug.print("rejected: {s}\n", .{@errorName(err)}),
}
```

## Freeing Claims

Both `decode` and `verify` return allocated claims. Call `free` when you
are done with them.

```zig
jwt.free(heap, claims);
```

**Remarks:** `free` accepts the return value of `decode` and `verify`.
Passing a value that owns no heap memory is a compile error.
