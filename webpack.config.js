const path = require("path");

module.exports = {
  entry: "./src/assets/ts/dashboard.ts",
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
    filename: "dashboard.js",
    path: path.resolve(__dirname, "src/assets/js"),
    clean: true,
  },
  devtool: "source-map",
  externals: {
    alpinejs: "Alpine",
    "fuse.js": "Fuse",
  },
};
