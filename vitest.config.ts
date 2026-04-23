import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts', 'tests/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'lcov'],
      include: ['src/**/*.ts'],
      exclude: [
        'src/main.ts',
        'src/app.ts',
        'src/ui/**',
        'src/**/*.d.ts',
        'src/**/*.test.ts',
      ],
    },
  },
});
