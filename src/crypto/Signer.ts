import * as crypto from "crypto";

/**
 * Sign a message with a private key
 * @param privateKey The private key in PEM format
 * @param message The message to sign
 * @returns The signature as a base64 string
 */
export function signMessage(privateKey: string, message: string): string {
  try {
    const keyType = detectKeyType(privateKey);

    if (keyType === "ed25519") {
      // Use the modern API for Ed25519
      const signature = crypto.sign(null, Buffer.from(message), {
        key: privateKey,
        format: "pem",
      });

      return signature.toString("base64");
    } else {
      // Use the traditional API for RSA
      const sign = crypto.createSign("SHA256");
      sign.update(message);
      sign.end();

      return sign.sign(privateKey, "base64");
    }
  } catch (error: any) {
    console.error("Error signing message:", error);
    throw new Error(`Failed to sign message: ${error.message}`);
  }
}

/**
 * Verify a signature with a public key
 * @param publicKey The public key in PEM format
 * @param message The original message
 * @param signature The signature to verify (base64 string)
 * @returns True if the signature is valid, false otherwise
 */
export function verifySignature(
  publicKey: string,
  message: string,
  signature: string,
): boolean {
  if (!publicKey || !message || !signature) {
    return false;
  }
  if (!publicKey.includes("-----BEGIN") || !publicKey.includes("-----END")) {
    return false;
  }

  try {
    const keyType = detectKeyType(publicKey);

    if (keyType === "ed25519") {
      // Use the modern API for Ed25519
      return crypto.verify(
        null,
        Buffer.from(message),
        {
          key: publicKey,
          format: "pem",
        },
        Buffer.from(signature, "base64"),
      );
    } else {
      // Use the traditional API for RSA
      const verify = crypto.createVerify("SHA256");
      verify.update(message);
      verify.end();

      return verify.verify(publicKey, signature, "base64");
    }
  } catch (error) {
    console.error("Error verifying signature:", error);
    return false;
  }
}

/**
 * Detects the type of key based on its PEM content
 * @param key The key in PEM format
 * @returns 'rsa' or 'ed25519'
 */
function detectKeyType(key: string): "rsa" | "ed25519" {
  try {
    // For ED25519 keys in PKCS#8 format, the key is shorter
    // RSA keys are much longer due to their modulus
    const keyObj = crypto.createPublicKey({
      key: key,
      format: "pem",
    });

    const keyType = keyObj.asymmetricKeyType;

    if (keyType === "ed25519") {
      return "ed25519";
    } else {
      return "rsa";
    }
  } catch (e) {
    // If we can't create a key object, try some heuristics
    if (key.includes("BEGIN PRIVATE KEY") && key.length < 400) {
      // ED25519 private keys are much shorter than RSA
      return "ed25519";
    } else if (key.includes("BEGIN PUBLIC KEY") && key.length < 300) {
      // ED25519 public keys are much shorter than RSA
      return "ed25519";
    }

    // Default to RSA as fallback
    return "rsa";
  }
}
