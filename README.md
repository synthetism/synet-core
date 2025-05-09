# @synet/core

Core cryptographic and identity primitives for Synet agents.

## Installation
```
npm install @synet/core**
```
## Features

* Key management (RSA and Ed25519)
* Digital signatures
* Cryptographic hashing
* Identity derivation
* Zero dependencies

## Usage

### Key Management

Generate cryptographic key pairs, derive public keys from private keys, and manage key identities:

```typescript
import { generateKeyPair, derivePublicKey, getShortId } from '@synet/core';

// Generate a new Ed25519 key pair
const keyPair = generateKeyPair('ed25519');
console.log('Private key:', keyPair.privateKey);
console.log('Public key:', keyPair.publicKey);

// Derive a public key from an existing private key
const derivedPublic = derivePublicKey(keyPair.privateKey);
console.log('Derived public key matches:', derivedPublic === keyPair.publicKey);

// Generate a short ID for a key (useful for display)
const shortId = getShortId(keyPair.publicKey);
console.log('Key short ID:', shortId); // e.g., "3f7b2a1c8e9d4f6a"
```

### Digital Signatures

Create and verify cryptographic signatures for message authentication:

```typescript
import { signMessage, verifySignature } from '@synet/core';

// Sign a message
const message = 'This message needs to be authenticated';
const signature = signMessage(keyPair.privateKey, message);

// Verify the signature
const isValid = verifySignature(keyPair.publicKey, message, signature);
console.log('Signature valid:', isValid); // true

// Tampering detection
const isForged = verifySignature(keyPair.publicKey, 'Forged message', signature);
console.log('Forged signature valid:', isForged); // false
```
### Cryptographic Hashing

Create secure hash digests in various formats:

```typescript
import { sha256Hex, sha256Base64, hashToAgentId } from '@synet/core';

// Create SHA-256 hash in hexadecimal format
const hexHash = sha256Hex('important data');
console.log('Hex hash:', hexHash);

// Create SHA-256 hash in base64 format
const base64Hash = sha256Base64('important data');
console.log('Base64 hash:', base64Hash);

// Generate an agent ID from a public key
const agentId = hashToAgentId(keyPair.publicKey);
console.log('Agent ID:', agentId); // e.g., "8f4d7c2b1a3e6d5f"
```

## API Reference

### Key Manager Functions

##### `generateKeyPair(type: 'rsa' | 'ed25519'): KeyPair`

Generates a new cryptographic key pair of the specified type.

#### `derivePublicKey(privateKey: string): string | null`

Extracts the public key from a private key.

#### `getShortId(publicKey: string): string`

Computes a 16-character hexadecimal identifier from a public key.

#### `getFingerprint(publicKey: string): string`

Computes a full 64-character hexadecimal fingerprint from a public key.

#### `generateWireGuardKeyPair(): { privateKey: string, publicKey: string }`

Generates Wireguard native Curve25519 (X25519) keypair exported in Base64

### Signer Functions

#### `signMessage(privateKey: string, message: string): string`

Signs a message with a private key, returning a base64-encoded signature.

#### `verifySignature(publicKey: string, message: string, signature: string): boolean`

Verifies a signature against a message using a public key.

### Hash Functions

#### `sha256Hex(data: string | Buffer): string`

Creates a SHA-256 hash of the input data in hexadecimal format.

#### `sha256Base64(data: string | Buffer): string`

Creates a SHA-256 hash of the input data in base64 format.

#### `hashToAgentId(publicKey: string): string`

Derives a 16-character agent identifier from a public key.

## Types

```typescript
type KeyType = 'rsa' | 'ed25519';

interface KeyPair {
  privateKey: string;
  publicKey: string;
  type: KeyType;
}
```

## Development

```typescript

# Install dependencies
npm install

# Run tests
npm test

# Run tests with coverage
npm run coverage

# Lint code
npm run lint

# Build the package
npm run build

```

## License

MIT
