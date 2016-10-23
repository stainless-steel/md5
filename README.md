# MD5 [![Version][version-img]][version-url] [![Status][status-img]][status-url]

The package provides the [MD5][1] hash function.

## [Documentation][documentation]

## Example

```rust
let digest = md5::compute(b"abcdefghijklmnopqrstuvwxyz");
assert_eq!(digest, [0xc3, 0xfc, 0xd3, 0xd7, 0x61, 0x92, 0xe4, 0x00,
                    0x7d, 0xfb, 0x49, 0x6c, 0xca, 0x67, 0xe1, 0x3b]);
```

## Contribution

Your contribution is highly appreciated. Do not hesitate to open an issue or a
pull request. Note that any contribution submitted for inclusion in the project
will be licensed according to the terms given in [LICENSE.md](LICENSE.md).

[1]: https://en.wikipedia.org/wiki/MD5

[documentation]: https://docs.rs/md5
[status-img]: https://travis-ci.org/stainless-steel/md5.svg?branch=master
[status-url]: https://travis-ci.org/stainless-steel/md5
[version-img]: https://img.shields.io/crates/v/md5.svg
[version-url]: https://crates.io/crates/md5
