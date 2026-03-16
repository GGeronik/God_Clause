import { createHash } from "crypto";

export interface ChainSeal {
  seal_id: string;
  from_entry_id: string;
  to_entry_id: string;
  entry_count: number;
  merkle_root: string;
  timestamp: string;
}

/**
 * Compute a Merkle root from a list of hex hash strings.
 * Uses a binary tree structure with SHA-256 at each node.
 */
export function computeMerkleRoot(hashes: string[]): string {
  if (hashes.length === 0) {
    return createHash("sha256").update("EMPTY").digest("hex");
  }
  if (hashes.length === 1) {
    return hashes[0];
  }

  let level = [...hashes];

  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : left; // duplicate last if odd
      const combined = createHash("sha256")
        .update(left + right)
        .digest("hex");
      next.push(combined);
    }
    level = next;
  }

  return level[0];
}
