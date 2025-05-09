import * as crypto from "node:crypto";
import nacl from 'tweetnacl';
import { encodeBase64 } from 'tweetnacl-util';


export type KeyType = "rsa" | "ed25519";

export interface KeyPair {
  privateKey: string;
  publicKey: string;
  type: KeyType;
}

/**
 * Generate a cryptographic key pair
 * @param type The type of key to generate ('rsa' or 'ed25519')
 * @returns A key pair object containing public and private keys
 */

export function generateKeyPair(type: KeyType): KeyPair {
  if (type === "rsa") {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: "spki",
        format: "pem",
      },
      privateKeyEncoding: {
        type: "pkcs8",
        format: "pem",
      },
    });

    return { publicKey, privateKey, type };
  }

  if (type === "ed25519") {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519", {
      publicKeyEncoding: {
        type: "spki",
        format: "pem",
      },
      privateKeyEncoding: {
        type: "pkcs8",
        format: "pem",
      },
    });

    return { publicKey, privateKey, type };
  }

  throw new Error(`Unsupported key type: ${type}`);
}

/**
 * Extract the public key from a private key
 * @param privateKey The private key in PEM format
 * @returns The corresponding public key in PEM format, or null if extraction fails
 */
export function derivePublicKey(privateKey: string): string | null {
  try {
    if (
      !privateKey ||
      !privateKey.includes("-----BEGIN") ||
      !privateKey.includes("-----END")
    ) {
      return null;
    }
    // Create a KeyObject from the private key PEM
    const privateKeyObj = crypto.createPrivateKey({
      key: privateKey,
      format: "pem",
    });

    // Derive the public key from the private key
    const publicKey = crypto.createPublicKey(privateKeyObj).export({
      type: "spki",
      format: "pem",
    });

    return publicKey.toString();
  } catch (error) {
    console.error("Failed to derive public key:", error);
    return null;
  }
}

/**
 * Compute a short identifier from a public key
 * @param publicKey The public key in PEM format
 * @returns A 16-character hexadecimal identifier
 */
export function getShortId(publicKey: string): string {
  const hash = crypto.createHash("sha256").update(publicKey).digest("hex");
  return hash.substring(0, 16);
}

/**
 * Compute a fingerprint from a public key
 * @param publicKey The public key in PEM format
 * @returns A 64-character hexadecimal fingerprint
 */
export function getFingerprint(publicKey: string): string {
  return crypto.createHash("sha256").update(publicKey).digest("hex");
}

/**
 * Generates a WireGuard-compatible key pair using TweetNaCl
 * @returns A key pair object with WireGuard-compatible keys
 */
export function generateWireGuardKeyPair(): { privateKey: string, publicKey: string } {
  // Generate a keypair using TweetNaCl's box (which uses Curve25519)
  const keyPair = nacl.box.keyPair();
  
  // Convert the Uint8Array keys to base64 strings as required by WireGuard
  return {
    privateKey: encodeBase64(keyPair.secretKey),
    publicKey: encodeBase64(keyPair.publicKey)
  };
}