import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    testTimeout: 60_000,
    hookTimeout: 60_000,
    // Shared Postgres: do not run files concurrently (TRUNCATE races).
    fileParallelism: false,
  },
})
