# `aws_sso_flow`

A Rust library for AWS SSO authentication.

## Installation

The crate is published to crates.io and can be added to a project using [`cargo add`](https://doc.rust-lang.org/cargo/commands/cargo-add.html):

```sh
cargo add aws_sso_flow
```

### TLS

Rustls is used for TLS support by default.
You can use a platform-specific implementation by disabling default features and enabling the `native-tls` feature:

```sh
cargo add aws_sso_flow --no-default-features --features native-tls
```

## Usage

See [docs.rs](https://docs.rs/aws_sso_flow) for complete usage documentation.

### Example

```rust
use std::convert::Infallible;

let credentials = aws_sso_flow::authenticate(|url| async move {
   println!("Go to {url} to sign in with SSO");
   Ok::<_, Infallible>(())
}).await?;
```

## Contributing

Pull requests are welcome.
For major changes, please open an issue first to discuss what you would like to change.

## License

[MIT](https://choosealicense.com/licenses/mit/)
