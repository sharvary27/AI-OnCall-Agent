import { defineConfig } from "vitest/config";

// Unit tests for the pure logic (src/checks.ts, src/detect.ts).
// A separate config, so tests don't load the Cloudflare Vite plugin
// from vite.config.ts.
export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    environment: "node"
  }
});