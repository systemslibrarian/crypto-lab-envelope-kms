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
      // Crypto and KMS code carry the security weight — gate them tightly.
      // UI/bootstrap is covered by manual exercise via the live demo.
      thresholds: {
        'src/crypto/**': {
          statements: 90,
          branches: 80,
          functions: 90,
          lines: 90,
        },
        'src/envelope/**': {
          statements: 85,
          branches: 75,
          functions: 85,
          lines: 85,
        },
        'src/kms/**': {
          statements: 80,
          branches: 70,
          functions: 80,
          lines: 80,
        },
      },
    },
  },
});
