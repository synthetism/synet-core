import { describe, it, expect } from 'vitest';
import { signMessage, verifySignature } from '../../src/crypto/Signer';
import { keyPairs, testMessage } from '../fixtures/keys';
import { generateKeyPair } from '../../src/identity/KeyManager';


describe('Signer', () => {
  for (const type of ['rsa', 'ed25519'] as const) {
    describe(`${type.toUpperCase()} signatures`, () => {
      const keys = keyPairs[type]
               
    
      it('should sign and verify a message correctly', () => {
        const signature = signMessage(keys.privateKey, testMessage);
        const isValid = verifySignature(keys.publicKey, testMessage, signature);
        expect(isValid).toBe(true);
      });

      it('should fail verification with a different message', () => {
        const signature = signMessage(keys.privateKey, testMessage);
        const isValid = verifySignature(keys.publicKey, 'forged message', signature);
        expect(isValid).toBe(false);
      });
      
      it('should fail verification with a wrong key', () => {
        const differentKeys = generateKeyPair(type);
        const signature = signMessage(keys.privateKey, testMessage);
        const isValid = verifySignature(differentKeys.publicKey, testMessage, signature);
        expect(isValid).toBe(false);
      });
    });
  }
  
  it('should handle invalid inputs gracefully', () => {
    const invalidKey = 'NOT A VALID KEY';
    const validKey = generateKeyPair('rsa').publicKey;
    
    // Should not throw errors
    expect(() => verifySignature(validKey, testMessage, 'invalid-signature')).not.toThrow();
    expect(verifySignature(validKey, testMessage, 'invalid-signature')).toBe(false);

    // Should throw errors
    expect(() => verifySignature(invalidKey, testMessage, 'invalid-signature')).toThrow();
       

  });


  it('should handle empty inputs gracefully', () => {
  

    // Should throw for missing inputs
    expect(() => verifySignature('', '', '')).toThrow();
    expect(() => signMessage('', '')).toThrow();
  

  });

});