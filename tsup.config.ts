import { defineConfig } from "tsup"

export default defineConfig({
  entry: {
    index: "src/index.ts",
    provider: "src/provider.ts",
  },
  format: ["esm"],
  target: "es2022",
  dts: true,
  sourcemap: true,
  clean: true,
})
