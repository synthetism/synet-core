import { describe, it, expect } from 'vitest';
import { keyPairs } from '../fixtures/keys';

import { 

  generateWireGuardKeyPair
} from '../../src/identity/KeyManager';

describe('WireGuard Key Functions', () => {
   
  describe('generateWireGuardKeyPair', () => {
    it('should generate valid WireGuard key pairs', () => {
      const { privateKey, publicKey } = generateWireGuardKeyPair();
      
      // Check format
      expect(privateKey).toBeTypeOf('string');
      expect(publicKey).toBeTypeOf('string');
      expect(privateKey.length).toBe(44);
      expect(publicKey.length).toBe(44);
      
      // Each should be different
      expect(privateKey).not.toBe(publicKey);
      
      // Should be valid base64
      expect(privateKey).toMatch(/^[A-Za-z0-9+/]+=*$/);
      expect(publicKey).toMatch(/^[A-Za-z0-9+/]+=*$/);
    });
  });
});