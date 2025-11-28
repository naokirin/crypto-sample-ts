import { describe, expect, it } from "vitest";
import {
  SSE_MASTER_KEY_LENGTH,
  SSE_TAG_LENGTH,
  decryptSSE,
  encryptSSE,
  generateSSEKey,
  generateSearchToken,
  generateDocumentId,
  searchSSE,
  type SSEDocument,
} from "../../src/searchable/sse.js";

describe("Searchable Symmetric Encryption (SSE)", () => {
  describe("Key Generation", () => {
    it("should generate a master key of correct length", () => {
      const key = generateSSEKey();
      expect(key.length).toBe(SSE_MASTER_KEY_LENGTH);
    });

    it("should generate different keys each time", () => {
      const key1 = generateSSEKey();
      const key2 = generateSSEKey();
      expect(key1).not.toEqual(key2);
    });
  });

  describe("Document ID Generation", () => {
    it("should generate a document ID of default length", () => {
      const id = generateDocumentId();
      expect(id.length).toBe(16);
    });

    it("should generate a document ID of specified length", () => {
      const id = generateDocumentId(32);
      expect(id.length).toBe(32);
    });

    it("should generate different IDs each time", () => {
      const id1 = generateDocumentId();
      const id2 = generateDocumentId();
      expect(id1).not.toEqual(id2);
    });
  });

  describe("Encryption and Decryption", () => {
    it("should encrypt and decrypt data correctly", async () => {
      const masterKey = generateSSEKey();
      const documentId = generateDocumentId();
      const plaintext = new TextEncoder().encode("Hello, World!");
      const keywords = ["hello", "world"];

      const encrypted = await encryptSSE(masterKey, documentId, plaintext, keywords);
      expect(encrypted.ciphertext).toBeDefined();
      expect(encrypted.authTag).toBeDefined();
      expect(encrypted.iv).toBeDefined();
      expect(encrypted.keywordTags).toHaveLength(2);
      expect(encrypted.keywordTags[0].length).toBe(SSE_TAG_LENGTH);
      expect(encrypted.keywordTags[1].length).toBe(SSE_TAG_LENGTH);

      const decrypted = await decryptSSE(masterKey, documentId, encrypted);
      expect(new TextDecoder().decode(decrypted)).toBe("Hello, World!");
    });

    it("should throw error for invalid master key length", async () => {
      const invalidKey = new Uint8Array(16); // 16バイト（32バイトが必要）
      const documentId = generateDocumentId();
      const plaintext = new TextEncoder().encode("test");
      const keywords = ["test"];

      await expect(encryptSSE(invalidKey, documentId, plaintext, keywords)).rejects.toThrow(
        "Invalid master key length"
      );
    });

    it("should work with empty plaintext", async () => {
      const masterKey = generateSSEKey();
      const documentId = generateDocumentId();
      const plaintext = new Uint8Array(0);
      const keywords = ["empty"];

      const encrypted = await encryptSSE(masterKey, documentId, plaintext, keywords);
      const decrypted = await decryptSSE(masterKey, documentId, encrypted);
      expect(decrypted).toEqual(plaintext);
    });

    it("should work with large plaintext", async () => {
      const masterKey = generateSSEKey();
      const documentId = generateDocumentId();
      const plaintext = new Uint8Array(10000).fill(42);
      const keywords = ["large"];

      const encrypted = await encryptSSE(masterKey, documentId, plaintext, keywords);
      const decrypted = await decryptSSE(masterKey, documentId, encrypted);
      expect(decrypted).toEqual(plaintext);
    });

    it("should work with multiple keywords", async () => {
      const masterKey = generateSSEKey();
      const documentId = generateDocumentId();
      const plaintext = new TextEncoder().encode("Test document");
      const keywords = ["test", "document", "example", "sample"];

      const encrypted = await encryptSSE(masterKey, documentId, plaintext, keywords);
      expect(encrypted.keywordTags).toHaveLength(4);
      expect(encrypted.keywordTags.every((tag) => tag.length === SSE_TAG_LENGTH)).toBe(true);

      const decrypted = await decryptSSE(masterKey, documentId, encrypted);
      expect(new TextDecoder().decode(decrypted)).toBe("Test document");
    });

    it("should generate different tags for different keywords", async () => {
      const masterKey = generateSSEKey();
      const documentId = generateDocumentId();
      const plaintext = new TextEncoder().encode("Test");
      const keywords1 = ["keyword1"];
      const keywords2 = ["keyword2"];

      const encrypted1 = await encryptSSE(masterKey, documentId, plaintext, keywords1);
      const encrypted2 = await encryptSSE(masterKey, documentId, plaintext, keywords2);

      expect(encrypted1.keywordTags[0]).not.toEqual(encrypted2.keywordTags[0]);
    });

    it("should generate same tags for same keywords", async () => {
      const masterKey = generateSSEKey();
      const documentId1 = generateDocumentId();
      const documentId2 = generateDocumentId();
      const plaintext = new TextEncoder().encode("Test");
      const keywords = ["same"];

      const encrypted1 = await encryptSSE(masterKey, documentId1, plaintext, keywords);
      const encrypted2 = await encryptSSE(masterKey, documentId2, plaintext, keywords);

      // 同じキーワードからは同じタグが生成される
      expect(encrypted1.keywordTags[0]).toEqual(encrypted2.keywordTags[0]);
    });
  });

  describe("Search Token Generation", () => {
    it("should generate a search tag of correct length", async () => {
      const masterKey = generateSSEKey();
      const keyword = "test";

      const searchTag = await generateSearchToken(masterKey, keyword);
      expect(searchTag.length).toBe(SSE_TAG_LENGTH);
    });

    it("should generate same tag for same keyword", async () => {
      const masterKey = generateSSEKey();
      const keyword = "test";

      const tag1 = await generateSearchToken(masterKey, keyword);
      const tag2 = await generateSearchToken(masterKey, keyword);
      expect(tag1).toEqual(tag2);
    });

    it("should generate different tags for different keywords", async () => {
      const masterKey = generateSSEKey();

      const tag1 = await generateSearchToken(masterKey, "keyword1");
      const tag2 = await generateSearchToken(masterKey, "keyword2");
      expect(tag1).not.toEqual(tag2);
    });

    it("should throw error for invalid master key length", async () => {
      const invalidKey = new Uint8Array(16);

      await expect(generateSearchToken(invalidKey, "test")).rejects.toThrow(
        "Invalid master key length"
      );
    });
  });

  describe("Search", () => {
    it("should find documents with matching keyword", async () => {
      const masterKey = generateSSEKey();
      const documents: SSEDocument[] = [];

      // 複数のドキュメントを暗号化
      const doc1Id = generateDocumentId();
      const doc1 = await encryptSSE(masterKey, doc1Id, new TextEncoder().encode("Document 1"), [
        "hello",
        "world",
      ]);
      documents.push(doc1);

      const doc2Id = generateDocumentId();
      const doc2 = await encryptSSE(masterKey, doc2Id, new TextEncoder().encode("Document 2"), [
        "test",
        "example",
      ]);
      documents.push(doc2);

      const doc3Id = generateDocumentId();
      const doc3 = await encryptSSE(masterKey, doc3Id, new TextEncoder().encode("Document 3"), [
        "hello",
        "test",
      ]);
      documents.push(doc3);

      // "hello"で検索
      const searchTag = await generateSearchToken(masterKey, "hello");
      const results = searchSSE(searchTag, documents);

      // doc1とdoc3が一致するはず
      expect(results.documents).toHaveLength(2);
      expect(results.documents).toContain(doc1);
      expect(results.documents).toContain(doc3);
      expect(results.documents).not.toContain(doc2);
    });

    it("should return empty results when no documents match", async () => {
      const masterKey = generateSSEKey();
      const documents: SSEDocument[] = [];

      const doc1Id = generateDocumentId();
      const doc1 = await encryptSSE(masterKey, doc1Id, new TextEncoder().encode("Document 1"), [
        "hello",
        "world",
      ]);
      documents.push(doc1);

      // 存在しないキーワードで検索
      const searchTag = await generateSearchToken(masterKey, "nonexistent");
      const results = searchSSE(searchTag, documents);

      expect(results.documents).toHaveLength(0);
    });

    it("should handle empty document list", async () => {
      const masterKey = generateSSEKey();
      const documents: SSEDocument[] = [];

      const searchTag = await generateSearchToken(masterKey, "test");
      const results = searchSSE(searchTag, documents);

      expect(results.documents).toHaveLength(0);
    });

    it("should throw error for invalid search tag length", () => {
      const documents: SSEDocument[] = [];
      const invalidTag = new Uint8Array(16); // 16バイト（32バイトが必要）

      expect(() => searchSSE(invalidTag, documents)).toThrow("Invalid search tag length");
    });

    it("should find documents with multiple matching keywords", async () => {
      const masterKey = generateSSEKey();
      const documents: SSEDocument[] = [];

      const doc1Id = generateDocumentId();
      const doc1 = await encryptSSE(masterKey, doc1Id, new TextEncoder().encode("Document 1"), [
        "keyword1",
        "keyword2",
        "keyword3",
      ]);
      documents.push(doc1);

      // keyword1で検索
      const searchTag1 = await generateSearchToken(masterKey, "keyword1");
      const results1 = searchSSE(searchTag1, documents);
      expect(results1.documents).toHaveLength(1);
      expect(results1.documents).toContain(doc1);

      // keyword2で検索
      const searchTag2 = await generateSearchToken(masterKey, "keyword2");
      const results2 = searchSSE(searchTag2, documents);
      expect(results2.documents).toHaveLength(1);
      expect(results2.documents).toContain(doc1);

      // keyword3で検索
      const searchTag3 = await generateSearchToken(masterKey, "keyword3");
      const results3 = searchSSE(searchTag3, documents);
      expect(results3.documents).toHaveLength(1);
      expect(results3.documents).toContain(doc1);
    });
  });

  describe("Integration Test", () => {
    it("should perform complete workflow: encrypt, search, and decrypt", async () => {
      const masterKey = generateSSEKey();
      const documents: SSEDocument[] = [];

      // ドキュメント1を暗号化
      const doc1Id = generateDocumentId();
      const doc1Plaintext = new TextEncoder().encode("This is document 1 about cryptography");
      const doc1 = await encryptSSE(masterKey, doc1Id, doc1Plaintext, [
        "cryptography",
        "document",
        "security",
      ]);
      documents.push(doc1);

      // ドキュメント2を暗号化
      const doc2Id = generateDocumentId();
      const doc2Plaintext = new TextEncoder().encode("This is document 2 about encryption");
      const doc2 = await encryptSSE(masterKey, doc2Id, doc2Plaintext, [
        "encryption",
        "document",
        "algorithm",
      ]);
      documents.push(doc2);

      // ドキュメント3を暗号化
      const doc3Id = generateDocumentId();
      const doc3Plaintext = new TextEncoder().encode("This is document 3 about security");
      const doc3 = await encryptSSE(masterKey, doc3Id, doc3Plaintext, [
        "security",
        "document",
        "cryptography",
      ]);
      documents.push(doc3);

      // "cryptography"で検索
      const searchTag = await generateSearchToken(masterKey, "cryptography");
      const results = searchSSE(searchTag, documents);

      // doc1とdoc3が一致するはず
      expect(results.documents).toHaveLength(2);
      expect(results.documents).toContain(doc1);
      expect(results.documents).toContain(doc3);
      expect(results.documents).not.toContain(doc2);

      // 検索結果を復号
      const decrypted1 = await decryptSSE(masterKey, doc1Id, doc1);
      const decrypted3 = await decryptSSE(masterKey, doc3Id, doc3);

      expect(new TextDecoder().decode(decrypted1)).toBe("This is document 1 about cryptography");
      expect(new TextDecoder().decode(decrypted3)).toBe("This is document 3 about security");
    });
  });
});
