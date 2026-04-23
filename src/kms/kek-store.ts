export type KekStatus = 'active' | 'decrypt-only' | 'pending-deletion';

export type KekVersionRecord = {
  version: number;
  createdAt: string;
  status: KekStatus;
  notAfter?: string;
  material: Uint8Array;
};

export type KekMetadata = {
  keyId: string;
  spec: string;
  createdAt: string;
  deletionWindowDays?: number;
  scheduledDeletionAt?: string;
  versions: Omit<KekVersionRecord, 'material'>[];
};

type KekStoreRecord = {
  keyId: string;
  spec: string;
  createdAt: string;
  deletionWindowDays?: number;
  scheduledDeletionAt?: string;
  versions: KekVersionRecord[];
};

function randomId(prefix: string): string {
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  return `${prefix}-${Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')}`;
}

export class KekStore {
  private readonly records = new Map<string, KekStoreRecord>();

  createKey(spec = 'AES256'): { keyId: string; version: number } {
    const keyId = randomId('kek');
    const material = crypto.getRandomValues(new Uint8Array(32));
    const now = new Date().toISOString();
    this.records.set(keyId, {
      keyId,
      spec,
      createdAt: now,
      versions: [{ version: 1, createdAt: now, status: 'active', material }],
    });
    return { keyId, version: 1 };
  }

  rotateKey(keyId: string): { keyId: string; version: number } {
    const record = this.mustGetRecord(keyId);
    const now = new Date().toISOString();
    for (const v of record.versions) {
      if (v.status === 'active') v.status = 'decrypt-only';
    }
    const version = record.versions.length + 1;
    record.versions.push({
      version,
      createdAt: now,
      status: 'active',
      material: crypto.getRandomValues(new Uint8Array(32)),
    });
    return { keyId, version };
  }

  scheduleDeletion(keyId: string, windowDays: number): void {
    const record = this.mustGetRecord(keyId);
    record.deletionWindowDays = windowDays;
    record.scheduledDeletionAt = new Date(Date.now() + windowDays * 24 * 60 * 60 * 1000).toISOString();
    for (const v of record.versions) {
      if (v.status === 'active') v.status = 'decrypt-only';
      v.notAfter = record.scheduledDeletionAt;
    }
  }

  getCurrentVersion(keyId: string): number {
    const record = this.mustGetRecord(keyId);
    const active = record.versions.find((v) => v.status === 'active');
    if (!active) throw new Error(`No active KEK version for ${keyId}`);
    return active.version;
  }

  getMaterialForWrap(keyId: string): { material: Uint8Array; version: number } {
    const record = this.mustGetRecord(keyId);
    const active = record.versions.find((v) => v.status === 'active');
    if (!active) throw new Error(`No active KEK version for ${keyId}`);
    return { material: active.material.slice(), version: active.version };
  }

  getMaterialForUnwrap(keyId: string, version: number): Uint8Array {
    const v = this.mustGetVersion(keyId, version);
    if (v.notAfter && Date.now() > new Date(v.notAfter).getTime()) {
      throw new Error(`KEK ${keyId} version ${version} is outside grace period`);
    }
    return v.material.slice();
  }

  exportMetadata(): KekMetadata[] {
    return Array.from(this.records.values()).map((r) => ({
      keyId: r.keyId,
      spec: r.spec,
      createdAt: r.createdAt,
      deletionWindowDays: r.deletionWindowDays,
      scheduledDeletionAt: r.scheduledDeletionAt,
      versions: r.versions.map(({ material: _material, ...v }) => v),
    }));
  }

  private mustGetRecord(keyId: string): KekStoreRecord {
    const record = this.records.get(keyId);
    if (!record) throw new Error(`Unknown keyId: ${keyId}`);
    return record;
  }

  private mustGetVersion(keyId: string, version: number): KekVersionRecord {
    const record = this.mustGetRecord(keyId);
    const v = record.versions.find((item) => item.version === version);
    if (!v) throw new Error(`Unknown KEK version ${version} for ${keyId}`);
    return v;
  }
}

export const kekStore = new KekStore();
