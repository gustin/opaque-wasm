



# Packing

    ./scripts/pack-it.sh

  Reference to 'wasm-pack' build options: https://rustwasm.github.io/docs/wasm-pack/commands/build.html

## Nightly

This needs to run on nightly to force clear_on_drop to not use cc compiler for wasm.

  rustup toolchain install nightly
  rustup override set nightly

