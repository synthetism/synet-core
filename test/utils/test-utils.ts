// In test/utils/test-utils.ts
import { KeyManager, KeyType, KeyPair } from '../../src/identity/KeyManager';

export function withKeyPair(type: KeyType, fn: (keyPair: KeyPair) => void): void {
  const keyPair = KeyManager.generateKeyPair(type);
  fn(keyPair);
}