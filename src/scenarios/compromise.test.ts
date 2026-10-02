import { describe, it, expect } from 'vitest';
import { runCompromise } from './compromise';

describe('KEK compromise with retained attacker copies', () => {
  for (const isolated of [false, true]) {
    it(`executes all four recovery stages (${isolated ? 'isolated' : 'shared'} KEKs)`, async () => {
      const rows = await runCompromise(isolated);
      const exposed = isolated ? [true, true, false, false] : [true, true, true, true];
      expect(rows).toHaveLength(4);
      for (const row of rows) {
        expect(row.archived).toEqual(exposed);
        expect(row.owner).toEqual([true, true, true, true]);
      }
      expect(rows[0].currentWrap).toEqual(exposed);
      expect(rows[1].currentWrap).toEqual(exposed); // Rotation is not re-wrap.
      expect(rows[2].currentWrap).toEqual([false, false, false, false]);
      expect(rows[2].currentRetained).toEqual(exposed); // Re-wrap is not recovery.
      expect(rows[3].currentRetained).toEqual([false, false, false, false]);
      expect(rows[3].currentWrap).toEqual([false, false, false, false]);
      expect(rows[0].future).toEqual([]);
      for (const row of rows.slice(1)) expect(row.future).toEqual([false, false, false, false]);
    });
  }
});
