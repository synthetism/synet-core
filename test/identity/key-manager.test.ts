import { describe, it, expect } from 'vitest';
import { derivePublicKey, getShortId, getFingerprint, generateKeyPair } from '../../src/identity/KeyManager';

describe('KeyManager', () => {
  const keyTypes = ['rsa', 'ed25519', 'wireguard'] as const;

  keyTypes.forEach((type) => {
    describe(`${type.toUpperCase()} key pair`, () => {
      const keys = generateKeyPair(type);

      it('should generate valid public and private keys', () => {
        expect(keys.privateKey).toBeTypeOf('string');
        expect(keys.publicKey).toBeTypeOf('string');
        expect(keys.type).toBe(type);

        if (type === 'wireguard') {
          // WireGuard keys are base64, not PEM
          expect(keys.privateKey).not.toContain('BEGIN');
          expect(keys.publicKey).not.toContain('BEGIN');
          expect(keys.privateKey.length).toBeGreaterThan(40);
          expect(keys.publicKey.length).toBeGreaterThan(40);
        } else {
          expect(keys.privateKey).toContain('BEGIN');
          expect(keys.publicKey).toContain('BEGIN');
        }
      });

      it('should generate a valid short ID', () => {
        const id = getShortId(keys.publicKey);
        expect(id.length).toBe(16);
        expect(id).toMatch(/^[a-f0-9]{16}$/);
      });

      it('should generate a valid fingerprint', () => {
        const fingerprint = getFingerprint(keys.publicKey);
        expect(fingerprint.length).toBe(64);
        expect(fingerprint).toMatch(/^[a-f0-9]{64}$/);
      });

      if (type !== 'wireguard') {
        it('should derive the correct public key from a private key', () => {
          const derivedPublicKey = derivePublicKey(keys.privateKey);
          const normalizedDerived = derivedPublicKey?.replace(/\s+/g, '');
          const normalizedOriginal = keys.publicKey.replace(/\s+/g, '');
          expect(normalizedDerived).toBe(normalizedOriginal);
        });

        it('should return null when deriving from invalid private key', () => {
          const invalidKey = 'NOT A VALID PRIVATE KEY';
          const result = derivePublicKey(invalidKey);
          expect(result).toBeNull();
        });
      }
    });
  });
});