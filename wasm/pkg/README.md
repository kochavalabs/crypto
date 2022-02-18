# Mazzaroth Crypto

Library that provides ed25519 crypto functions for Mazzaroth.

## Bundler

To use this package in browsers you must include the following bundler config:

```js
config.module
      .rule('wasm')
      .type('javascript/auto')
      .test(/\.wasm$/)
      .use('wasm')
      .loader('base64-loader')
      .end()
```
