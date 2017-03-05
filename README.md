# MD5 [![Package][package-img]][package-url] [![Documentation][documentation-img]][documentation-url] [![Build][build-img]][build-url]

The package provides the [MD5][1] hash function.

## Example

```rust
let digest = md5::compute(b"abcdefghijklmnopqrstuvwxyz");
assert_eq!(format!("{:x}", digest), "c3fcd3d76192e4007dfb496cca67e13b");
```

## Contribution

Your contribution is highly appreciated. Do not hesitate to open an issue or a
pull request. Note that any contribution submitted for inclusion in the project
will be licensed according to the terms given in [LICENSE.md](LICENSE.md).

[1]: https://en.wikipedia.org/wiki/MD5

[build-img]: https://travis-ci.org/stainless-steel/md5.svg?branch=master
[build-url]: https://travis-ci.org/stainless-steel/md5
[documentation-img]: https://docs.rs/md5/badge.svg
[documentation-url]: https://docs.rs/md5
[package-img]: https://img.shields.io/crates/v/md5.svg
[package-url]: https://crates.io/crates/md5
