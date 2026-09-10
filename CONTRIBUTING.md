# Contributing to Selucid

## Building

```sh
# Core + CLI + TUI (no GUI deps)
cargo build --workspace

# GUI (needs gtk4-devel + libadwaita-devel)
cargo build -p selucid-gui --features gui
```

## Testing

```sh
cargo test --workspace
```

## Linting

```sh
cargo clippy --workspace --all-targets
```

## Code style

- `cargo fmt --check` before committing.
- Doc comments on all `pub` items.
- No `unwrap()` in production paths (tests excepted).

## License

GPL-3.0-or-later.
