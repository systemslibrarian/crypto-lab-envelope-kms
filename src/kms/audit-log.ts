import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, encoder } from '../crypto/bytes';

export type AuditOperation =
  | 'CreateKey'
  | 'GenerateDataKey'
  | 'Decrypt'
  | 'ReEncrypt'
  | 'RotateKey'
  | 'ScheduleKeyDeletion'
  | 'Seal'
  | 'Open'
  | 'RewrapEnvelope';

export type AuditEntry = {
  index: number;
  timestamp: string;
  operation: AuditOperation;
  principal: string;
  keyId?: string;
  kekVersion?: number;
  success: boolean;
  prev_hash: string;
  details?: string;
  hash: string;
};

function canonicalize(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((v) => canonicalize(v)).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalize(v)}`).join(',')}}`;
}

function hashEntry(payload: Omit<AuditEntry, 'hash'>): string {
  return bytesToHex(sha256(encoder.encode(canonicalize(payload))));
}

export class AuditLog {
  private entries: AuditEntry[] = [];

  constructor() {
    this.entries = this.load();
  }

  append(entry: Omit<AuditEntry, 'index' | 'timestamp' | 'prev_hash' | 'hash'>): AuditEntry {
    const index = this.entries.length;
    const prev_hash = index === 0 ? 'GENESIS' : this.entries[index - 1].hash;
    const timestamp = new Date().toISOString();
    const payload = { index, timestamp, prev_hash, ...entry };
    const hash = hashEntry(payload);
    const out: AuditEntry = { ...payload, hash };
    this.entries.push(out);
    this.persist();
    return out;
  }

  list(): AuditEntry[] {
    return this.entries.map((e) => ({ ...e }));
  }

  tamper(index: number, details: string): void {
    const target = this.entries[index];
    if (!target) throw new Error('Invalid audit index');
    target.details = details;
    this.persist();
  }

  verify(): { ok: boolean; brokenIndex: number | null } {
    for (let i = 0; i < this.entries.length; i += 1) {
      const entry = this.entries[i];
      const expectedPrev = i === 0 ? 'GENESIS' : this.entries[i - 1].hash;
      if (entry.prev_hash !== expectedPrev) return { ok: false, brokenIndex: i };
      const { hash: _hash, ...payload } = entry;
      const recomputed = hashEntry(payload);
      if (recomputed !== entry.hash) return { ok: false, brokenIndex: i };
    }
    return { ok: true, brokenIndex: null };
  }

  private persist(): void {
    localStorage.setItem('audit-log-v1', JSON.stringify(this.entries));
  }

  private load(): AuditEntry[] {
    const raw = localStorage.getItem('audit-log-v1');
    if (!raw) return [];
    try {
      const parsed = JSON.parse(raw) as AuditEntry[];
      if (!Array.isArray(parsed)) return [];
      return parsed;
    } catch {
      return [];
    }
  }
}

export const auditLog = new AuditLog();
