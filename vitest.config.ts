import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    server: {
      deps: {
        // These packages are externalized by default, so Node resolves their bare
        // imports. That broke when @fluentui/react-tabster 9.26.17 dropped its
        // "node" export condition: the package now loads as ESM and named-imports
        // tabster, which publishes no "exports" map, so Node picks the CommonJS
        // entry and cannot see the named exports. Inlining the pair lets Vite
        // resolve tabster through its "module" field instead.
        inline: [/node_modules\/@fluentui\//, /node_modules\/tabster\//],
      },
    },
    setupFiles: ["src/test-setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
    globals: true,
  },
});
