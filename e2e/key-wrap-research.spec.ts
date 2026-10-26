import { expect, test } from '@playwright/test';

test('key-wrap research qualifies the observation and padding-dependent bound', async ({
  page,
}) => {
  await page.goto('.');
  const note = page.locator('#key-wrap-research-note');
  for (const text of [
    'preprint',
    'trusted expected plaintext length',
    '32-byte',
    '66-byte',
    'six padding bytes',
    'not a universal',
    'single-block',
    'replay',
  ]) {
    await expect(note).toContainText(text);
  }
  await expect(note.locator('a')).toHaveAttribute('href', 'https://eprint.iacr.org/2026/2636');
});
