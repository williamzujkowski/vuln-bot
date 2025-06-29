const path = require("path");

module.exports = {
  entry: {
    dashboard: "./src/assets/ts/dashboard.ts",
    "offline-support": "./src/assets/ts/offline-support.ts",
    "image-optimization": "./src/assets/ts/image-optimization.ts",
  },
  mode: "production",
  module: {
    rules: [
      {
        test: /\.ts$/,
        use: "ts-loader",
        exclude: /node_modules/,
      },
    ],
  },
  resolve: {
    extensions: [".ts", ".js"],
  },
  output: {
    filename: "[name].js",
    path: path.resolve(__dirname, "src/assets/js"),
    clean: true,
  },
  devtool: "source-map",
  externals: {
    alpinejs: "Alpine",
    "fuse.js": "Fuse",
  },
};
