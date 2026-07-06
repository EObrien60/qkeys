import { fileURLToPath } from "node:url"
import { defineConfig } from "vitest/config"

// Resolve @obh/api-keys to its source so the middleware tests run without a
// prior build of the core package.
export default defineConfig({
  test: {
    include: ["src/**/*.test.ts"],
    environment: "node",
  },
  resolve: {
    alias: {
      "@obh/api-keys": fileURLToPath(new URL("../api-keys/src/index.ts", import.meta.url)),
    },
  },
})
