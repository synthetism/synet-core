import { describe, it, expect } from 'vitest';
import { sha256Hex, sha256Base64, hashToAgentId } from '../../src/crypto/Hash';
import { keyPairs } from '../fixtures/keys';

describe('Hash functions', () => {
  const testInput = 'Synet hash test message';
  const testBuffer = Buffer.from(testInput, 'utf8');
  
  describe('sha256Hex', () => {
    it('should hash a string correctly', () => {
      const hash = sha256Hex(testInput);
      expect(hash).toBeTypeOf('string');
      expect(hash.length).toBe(64); // SHA-256 hex is 64 chars
      expect(hash).toMatch(/^[a-f0-9]{64}$/); // Only hex chars
    });
    
    it('should hash a buffer correctly', () => {
      const hash = sha256Hex(testBuffer);
      expect(hash).toBeTypeOf('string');
      expect(hash.length).toBe(64);
    });
    
    it('should be deterministic', () => {
      const hash1 = sha256Hex(testInput);
      const hash2 = sha256Hex(testInput);
      expect(hash1).toBe(hash2);
    });
    
    it('should produce different hashes for different inputs', () => {
      const hash1 = sha256Hex(testInput);
      const hash2 = sha256Hex(`${testInput} modified`);
      expect(hash1).not.toBe(hash2);
    });
  });
  
  describe('sha256Base64', () => {
    it('should hash a string correctly', () => {
      const hash = sha256Base64(testInput);
      expect(hash).toBeTypeOf('string');
      // Base64 encoded SHA-256 is ~44 chars, often with padding
      expect(hash.length).toBeGreaterThanOrEqual(43);
      expect(hash.length).toBeLessThanOrEqual(44);
      // Should be valid base64
      expect(hash).toMatch(/^[A-Za-z0-9+/]+=*$/);
    });
    
    it('should hash a buffer correctly', () => {
      const hash = sha256Base64(testBuffer);
      expect(hash).toBeTypeOf('string');
      expect(hash.length).toBeGreaterThanOrEqual(43);
      expect(hash.length).toBeLessThanOrEqual(44);
    });
    
    it('should be deterministic', () => {
      const hash1 = sha256Base64(testInput);
      const hash2 = sha256Base64(testInput);
      expect(hash1).toBe(hash2);
    });
    
    it('should produce different hashes for different inputs', () => {
      const hash1 = sha256Base64(testInput);
      const hash2 = sha256Base64(`${testInput} modified`);
      expect(hash1).not.toBe(hash2);
    });
  });
  
  describe('hashToAgentId', () => {
    it('should create a valid agent ID from a public key', () => {
      // Test with both key types
      for (const type of ['rsa', 'ed25519']) {
        const publicKey = keyPairs[type].publicKey;
        const agentId = hashToAgentId(publicKey);
        
        expect(agentId).toBeTypeOf('string');
        expect(agentId.length).toBe(16);
        expect(agentId).toMatch(/^[a-f0-9]{16}$/);
      }
    });
    
    it('should produce consistent agent IDs for the same public key', () => {
      const publicKey = keyPairs.rsa.publicKey;
      const id1 = hashToAgentId(publicKey);
      const id2 = hashToAgentId(publicKey);
      expect(id1).toBe(id2);
    });
    
    it('should produce different agent IDs for different public keys', () => {
      const id1 = hashToAgentId(keyPairs.rsa.publicKey);
      const id2 = hashToAgentId(keyPairs.ed25519.publicKey);
      expect(id1).not.toBe(id2);
    });
    
    it('should match the first 16 chars of the full hex hash', () => {
      const publicKey = keyPairs.rsa.publicKey;
      const fullHash = sha256Hex(publicKey);
      const agentId = hashToAgentId(publicKey);
      expect(agentId).toBe(fullHash.slice(0, 16));
    });
  });

  describe('Edge cases', () => {
    it('should handle empty string input', () => {
      const hexHash = sha256Hex('');
      const base64Hash = sha256Base64('');
      
      // These are the correct SHA-256 hashes for an empty string
      expect(hexHash).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
      expect(base64Hash).toBe('47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=');
    });
    
    it('should handle unicode characters', () => {
      const input = 'Synet 网络 réseau 네트워크';
      expect(() => sha256Hex(input)).not.toThrow();
      expect(() => sha256Base64(input)).not.toThrow();
      expect(() => hashToAgentId(input)).not.toThrow();
      
      // Check consistency with unicode input
      const hash1 = sha256Hex(input);
      const hash2 = sha256Hex(input);
      expect(hash1).toBe(hash2);
    });
  });
});