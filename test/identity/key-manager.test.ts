import { describe, it, expect } from 'vitest';
import {  derivePublicKey,getShortId , getFingerprint } from '../../src/identity/KeyManager';
import { keyPairs } from '../fixtures/keys';

describe('KeyManager', () => {
  ['rsa', 'ed25519'].forEach((type) => {
    describe(`${type.toUpperCase()} key pair`, () => {
    
      const keys = keyPairs[type];

      it('should generate valid public and private keys', () => {
        expect(keys.privateKey).toBeTypeOf('string');
        expect(keys.publicKey).toBeTypeOf('string');
        expect(keys.type).toBe(type);
        expect(keys.privateKey).toContain('BEGIN');
        expect(keys.publicKey).toContain('BEGIN');
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

      it('should derive the correct public key from a private key', () => {
        // Get the derived public key
        const derivedPublicKey = derivePublicKey(keys.privateKey);
        
        // Clean up whitespace and line breaks for comparison
        const normalizedDerived = derivedPublicKey?.replace(/\s+/g, '');
        const normalizedOriginal = keys.publicKey.replace(/\s+/g, '');
        
        // Verify the derived key matches the original public key
        expect(normalizedDerived).toBe(normalizedOriginal);
      });

      // Add this test to verify behavior with invalid input
      it('should return null when deriving from invalid private key', () => {
        const invalidKey = 'NOT A VALID PRIVATE KEY';
        const result = derivePublicKey(invalidKey);
        expect(result).toBeNull();
      });

    });
  });
});
