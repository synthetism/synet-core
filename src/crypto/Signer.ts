import * as crypto from "node:crypto";

/**
 * Sign a message with a private key
 * @param privateKey The private key in PEM format
 * @param message The message to sign
 * @returns The signature as a base64 string
 * @throws {Error} If inputs are invalid or signing fails
 */
export function signMessage(privateKey: string, message: string): string {
  try {
    if (!privateKey || !message) {
      throw new Error("Invalid input: privateKey and message are required");
    }
    const keyType = detectKeyType(privateKey);

    if (keyType === "ed25519") {
      // Use the modern API for Ed25519
      const signature = crypto.sign(null, Buffer.from(message), {
        key: privateKey,
        format: "pem",
      });

      return signature.toString("base64");
    }

    // Use the traditional API for RSA
    const sign = crypto.createSign("SHA256");
    sign.update(message);
    sign.end();

    return sign.sign(privateKey, "base64");
  } catch (error: unknown) {
    //console.error("Error signing message:", error);

    if (error instanceof Error) {
      throw new Error(`Failed to sign message: ${error.message}`);
    }
    throw new Error("Failed to sign message: Unknown error");
  }
}

/**
 * Verify a signature with a public key
 * @param publicKey The public key in PEM format
 * @param message The original message
 * @param signature The signature to verify (base64 string)
 * @returns True if the signature is valid, false otherwise
 * @throws {Error} If inputs are invalid or signing fails
 */
export function verifySignature(
  publicKey: string,
  message: string,
  signature: string,
): boolean {
  if (!publicKey || !message || !signature) {
    throw new Error(
      "Invalid input: publicKey, message and signature are required",
    );
  }

  if (!publicKey.includes("-----BEGIN") || !publicKey.includes("-----END")) {
    throw new Error("Invalid publicKey format: PEM format required");
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
    }

    // Use the traditional API for RSA
    const verify = crypto.createVerify("SHA256");
    verify.update(message);
    verify.end();

    return verify.verify(publicKey, signature, "base64");
  } catch (error: unknown) {
    console.error("Error signing message:", error);

    if (error instanceof Error) {
      throw new Error(`Failed to verify signature: ${error.message}`);
    }

    throw new Error("Failed to verify signature: Unknown error");
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
    }

    return "rsa";
  } catch (_e) {
    // If we can't create a key object, try some heuristics
    if (key.includes("BEGIN PRIVATE KEY") && key.length < 400) {
      // ED25519 private keys are much shorter than RSA
      return "ed25519";
    }

    if (key.includes("BEGIN PUBLIC KEY") && key.length < 300) {
      // ED25519 public keys are much shorter than RSA
      return "ed25519";
    }

    // Default to RSA as fallback
    return "rsa";
  }
}
