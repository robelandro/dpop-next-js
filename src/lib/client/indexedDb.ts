/**
 * IndexedDB storage adapter for Non-Extractable Web Cryptography CryptoKey objects.
 * 
 * In standard HTML5, the Structured Clone Algorithm natively allows storing
 * non-extractable CryptoKey instances in IndexedDB.
 * Even if an attacker gains XSS execution, they CANNOT export the raw private key
 * bytes because crypto.subtle.exportKey will throw DOMException: 'key is not extractable'.
 */

const DB_NAME = 'dpop_secure_keystore_v1';
const DB_VERSION = 1;
const STORE_NAME = 'dpop_crypto_keys';
const KEY_RECORD_ID = 'current_client_dpop_key';

export interface StoredKeyRecord {
  id: string;
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  publicKeyJwk: {
    kty: 'EC';
    crv: string;
    x: string;
    y: string;
  };
  jkt: string;
  createdAt: number;
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (typeof window === 'undefined' || !window.indexedDB) {
      return reject(new Error('IndexedDB is not supported in this environment'));
    }

    const request = window.indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: 'id' });
      }
    };

    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

export async function storeNonExtractableKey(record: Omit<StoredKeyRecord, 'id'>): Promise<void> {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const store = tx.objectStore(STORE_NAME);

    const fullRecord: StoredKeyRecord = {
      ...record,
      id: KEY_RECORD_ID,
    };

    const request = store.put(fullRecord);

    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
    tx.oncomplete = () => db.close();
  });
}

export async function getNonExtractableKey(): Promise<StoredKeyRecord | null> {
  try {
    const db = await openDatabase();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const store = tx.objectStore(STORE_NAME);
      const request = store.get(KEY_RECORD_ID);

      request.onsuccess = () => {
        resolve(request.result || null);
      };
      request.onerror = () => reject(request.error);
      tx.oncomplete = () => db.close();
    });
  } catch {
    return null;
  }
}

export async function deleteNonExtractableKey(): Promise<void> {
  try {
    const db = await openDatabase();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);
      const request = store.delete(KEY_RECORD_ID);

      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
      tx.oncomplete = () => db.close();
    });
  } catch {
    // ignore
  }
}
