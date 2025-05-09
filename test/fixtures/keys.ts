// In test/fixtures/keys.ts
import { KeyManager } from '../../src/identity/KeyManager';

// Generate once and export
const rsaKeyPair = KeyManager.generateKeyPair('rsa');
const ed25519KeyPair = KeyManager.generateKeyPair('ed25519');

export const testMessage = 'Synet is rising.';

export const keyPairs = {
    rsa: rsaKeyPair,
    ed25519: ed25519KeyPair,
}