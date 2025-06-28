module.exports = {
  env: {
    browser: true,
    es2021: true,
    node: true,
  },
  extends: ["google"],
  parserOptions: {
    ecmaVersion: "latest",
    sourceType: "module",
  },
  rules: {
    "max-len": ["error", { code: 100, ignoreUrls: true, ignoreStrings: true }],
    "require-jsdoc": "off",
    "valid-jsdoc": "off",
  },
  ignorePatterns: ["node_modules/", "public/", "*.min.js"],
};