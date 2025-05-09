import * as crypto from "crypto";

export function sha256Hex(input: string | Buffer): string {
  return crypto.createHash("sha256").update(input).digest("hex");
}

export function sha256Base64(input: string | Buffer): string {
  return crypto.createHash("sha256").update(input).digest("base64");
}

export function hashToAgentId(publicKey: string): string {
  return sha256Hex(publicKey).slice(0, 16);
}
