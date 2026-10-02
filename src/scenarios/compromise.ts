import { aeadOpen, aeadSeal } from '../crypto/aead';
import { aesKwUnwrap, aesKwWrap } from '../crypto/aes-kw';
import { encoder, zeroize } from '../crypto/bytes';
import type { EnvelopeRecord } from '../envelope/seal';
import { KekStore } from '../kms/kek-store';

export type CompromiseStage = {
  name: string;
  archived: boolean[];
  currentWrap: boolean[];
  currentRetained: boolean[];
  future: boolean[];
  owner: boolean[];
};

// Isolated from the interactive KMS and its audit log. Every verdict is an actual
// RFC 3394 unwrap + AES-GCM open, or a GCM open with a previously recovered DEK.
export async function runCompromise(isolated: boolean): Promise<CompromiseStage[]> {
  const store = new KekStore();
  const a = store.createKey().keyId;
  const b = isolated ? store.createKey().keyId : a;
  const ids = [a, a, b, b];
  const seal = async (id: string, index: number): Promise<EnvelopeRecord> => {
    const { material, version } = store.getMaterialForWrap(id);
    const dek = crypto.getRandomValues(new Uint8Array(32));
    const aad = encoder.encode(index < 2 ? 'tenant=A' : 'tenant=B');
    try {
      const payload = await aeadSeal(encoder.encode(`record ${index}`), dek, aad);
      return {
        ...payload,
        aad,
        wrappedDEK: aesKwWrap(material, dek),
        kekId: id,
        kekVersion: version,
      };
    } finally {
      zeroize(material);
      zeroize(dek);
    }
  };
  const original = await Promise.all(ids.map(seal));
  // Deep copies matter: storage maintenance must never mutate the attacker's archive.
  const archived = original.map((e) => ({
    ...e,
    wrappedDEK: e.wrappedDEK.slice(),
    ciphertext: e.ciphertext.slice(),
    iv: e.iv.slice(),
    tag: e.tag.slice(),
    aad: e.aad.slice(),
  }));
  const stolen = store.getMaterialForUnwrap(a, 1);
  const retained = original.map((e) => {
    try {
      return aesKwUnwrap(stolen, e.wrappedDEK);
    } catch {
      return null;
    }
  });
  const openWithDek = async (e: EnvelopeRecord, dek: Uint8Array | null): Promise<boolean> => {
    if (!dek) return false;
    try {
      const plain = await aeadOpen(e.ciphertext, e.iv, e.tag, dek, e.aad);
      zeroize(plain);
      return true;
    } catch {
      return false;
    }
  };
  const attack = async (e: EnvelopeRecord): Promise<boolean> => {
    let dek: Uint8Array | null = null;
    try {
      dek = aesKwUnwrap(stolen, e.wrappedDEK);
      return await openWithDek(e, dek);
    } catch {
      return false;
    } finally {
      if (dek) zeroize(dek);
    }
  };
  const rows: CompromiseStage[] = [];
  let current = original;
  const record = async (name: string, future: EnvelopeRecord[] = []) => {
    rows.push({
      name,
      archived: await Promise.all(archived.map(attack)),
      currentWrap: await Promise.all(current.map(attack)),
      currentRetained: await Promise.all(current.map((e, i) => openWithDek(e, retained[i]))),
      future: await Promise.all(future.map(attack)),
      owner: await Promise.all(
        current.map(async (e) => {
          const kek = store.getMaterialForUnwrap(e.kekId, e.kekVersion);
          const dek = aesKwUnwrap(kek, e.wrappedDEK);
          try {
            return await openWithDek(e, dek);
          } finally {
            zeroize(kek);
            zeroize(dek);
          }
        }),
      ),
    });
  };
  try {
    await record('Before rotation');
    for (const id of new Set(ids)) store.rotateKey(id);
    const future = await Promise.all(ids.map(seal));
    await record('Rotate KEKs only', future);
    current = current.map((e) => {
      const old = store.getMaterialForUnwrap(e.kekId, e.kekVersion);
      const next = store.getMaterialForWrap(e.kekId);
      const dek = aesKwUnwrap(old, e.wrappedDEK);
      try {
        return { ...e, wrappedDEK: aesKwWrap(next.material, dek), kekVersion: next.version };
      } finally {
        zeroize(old);
        zeroize(next.material);
        zeroize(dek);
      }
    });
    await record('Re-wrap existing DEKs', future);
    current = await Promise.all(ids.map(seal));
    await record('Re-encrypt with fresh DEKs', future);
    return rows;
  } finally {
    zeroize(stolen);
    for (const dek of retained) if (dek) zeroize(dek);
    store.clear();
  }
}
