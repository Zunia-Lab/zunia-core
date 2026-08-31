import assert from "node:assert/strict";
import { test } from "node:test";
import { COIN_TYPES, KERNEL_VERSION } from "../src/index.ts";

test("scaffold exports kernel version", () => {
  assert.equal(KERNEL_VERSION, "0.0.0-scaffold");
});

test("default cosmos coin type is 118", () => {
  assert.equal(COIN_TYPES.cosmos, 118);
});

// Official BIP-39/32/44 vectors must be added before any crypto lands.
