const path = require('path');
const CopyPlugin = require("copy-webpack-plugin");

module.exports = {
  entry: {
    'greenpass-verify': './src/greenpass-verify.js'
  },
  output: {
    filename: '[name]-bundle.js',
    path: path.resolve(__dirname, 'dist'),
    library: {
      name: "GreenPassVerify",
      type: "var",
    },
    clean: true,
  },
  mode: 'development',
  devtool: 'eval-source-map',  // Generate detailed source maps.
  //devtool: 'source-map',  // Generate readable output.
  stats: {
      builtAt: true,  // Print build time, useful for "watch".
  },
  plugins: [
    new CopyPlugin({
      patterns: [
        { from: "src/index.html",          to: "." },
        { from: "sounds",                  to: "sounds" },
        { from: "3rd-party/zxing-library", to: "3rd-party/zxing-library" },
      ]
    })
  ]
};
