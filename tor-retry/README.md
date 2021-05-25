# tor-retry

Helpers to implement retry-related functionality.

Right now, this crate only has an error type that we use when we
retry something a few times, and they all fail.  Instead of
returning only a single error, it records _all of the errors
received, in case they are different.

This crate is part of
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.
It's used by higher-level crates that retry
operations.

### Design notes

XXXX We'll want to refactor this one.  It might be better in a
crate called retry-error or something, since it isn't
tor-specific.

The [`RetryError`] type might be more generally useful in the
future, if it gets a stable interface, and if we can make it stop
depending on [`anyhow`].

Maybe this error type should be parameterized on an input error type.

## Example

```rust
use tor_retry::RetryError;

const N_ATTEMPTS: usize = 10;
let mut err = RetryError::while_doing("perform an example operation");
for _ in 0..N_ATTEMPTS {
    match some_operation() {
        Ok(val) => return Ok(val),
        Err(e) => err.push(e),
    }
}
// All attempts failed; return all the errors.
return Err(err)
```

License: MIT OR Apache-2.0
