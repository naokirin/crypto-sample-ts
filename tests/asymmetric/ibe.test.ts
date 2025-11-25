/**
 * IBE（Identity-Based Encryption）のテスト
 *
 * 現在は基本的な動作確認のみ
 */

import { beforeAll, describe, expect, it } from "vitest";
import { initIBE, testIBE } from "../../src/asymmetric/ibe.js";

describe("IBE WebAssembly Module", () => {
  beforeAll(async () => {
    // WebAssemblyモジュールを初期化
    await initIBE();
  });

  it("should initialize WebAssembly module", async () => {
    await expect(initIBE()).resolves.not.toThrow();
  });

  it("should execute basic test function (add)", async () => {
    const result = await testIBE();
    expect(result).toBe(5); // 2 + 3 = 5
  });
});
