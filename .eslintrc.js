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
  ignorePatterns: ["node_modules/", "public/", "*.min.js", "dist/", "src/assets/js/dashboard.js"],
  overrides: [
    {
      files: ["**/*.ts"],
      parser: "@typescript-eslint/parser",
      plugins: ["@typescript-eslint"],
      extends: ["google"],
      parserOptions: {
        project: "./tsconfig.json",
        tsconfigRootDir: __dirname,
      },
      rules: {
        "max-len": ["error", { code: 100, ignoreUrls: true, ignoreStrings: true }],
        "require-jsdoc": "off",
        "valid-jsdoc": "off",
        "@typescript-eslint/no-explicit-any": "warn",
        "@typescript-eslint/no-unused-vars": "error",
        "@typescript-eslint/prefer-nullish-coalescing": "error",
        "@typescript-eslint/prefer-optional-chain": "error",
        "@typescript-eslint/no-unnecessary-type-assertion": "error",
      },
    },
    {
      files: ["tests/**/*.ts", "*.config.ts"],
      parser: "@typescript-eslint/parser",
      plugins: ["@typescript-eslint"],
      extends: ["google"],
      parserOptions: {
        project: "./tsconfig.test.json",
        tsconfigRootDir: __dirname,
      },
      rules: {
        "max-len": ["error", { code: 100, ignoreUrls: true, ignoreStrings: true }],
        "require-jsdoc": "off",
        "valid-jsdoc": "off",
        "@typescript-eslint/no-explicit-any": "off", // Allow any in tests
        "@typescript-eslint/no-unused-vars": "error",
        "no-unused-expressions": "off", // Allow chai assertions
      },
    },
  ],
};
