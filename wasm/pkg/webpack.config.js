module.exports = {
  entry: './src/crypto.js',
  output: {
    filename: 'crypto.js',
    library: {
      type: 'umd',
      name: 'crypto',
    },
    // prevent error: `Uncaught ReferenceError: self is not define`
    globalObject: 'this',
  },
  resolve: {
    fallback: {
      fs: false,
      util: false,
      crypto: false,
      path: false,
    }
  },
  module: {
    rules: [
      {
        type: 'javascript/auto',
        test: /\.wasm$/,
        use: 'base64-loader'
      }
    ]
  }
};
