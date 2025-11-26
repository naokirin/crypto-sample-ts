use wasm_bindgen::prelude::*;
use pqcrypto_std::mldsa::mldsa65::{PrivateKey, PublicKey, PRIVKEY_SIZE, PUBKEY_SIZE, SIG_SIZE};
use pqcrypto_std::mldsa::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;

// wasm-bindgenの初期化
#[wasm_bindgen(start)]
pub fn init() {
    // コンソールエラーハンドリングの設定
    console_error_panic_hook::set_once();
}

// Dilithium鍵ペアの型定義
#[wasm_bindgen]
pub struct DilithiumKeyPair {
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

#[wasm_bindgen]
impl DilithiumKeyPair {
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn private_key(&self) -> Vec<u8> {
        self.private_key.clone()
    }
}

/**
 * CRYSTALS-Dilithium鍵ペアを生成
 * ML-DSA-65を使用（NIST標準化されたDilithium、推奨レベル）
 * 
 * @returns 公開鍵と秘密鍵のペア
 */
#[wasm_bindgen]
pub fn generate_keypair() -> DilithiumKeyPair {
    // 乱数生成器を作成
    let mut rng = OsRng;
    
    // 公開鍵のバッファを準備
    let mut vk_bytes = [0u8; PUBKEY_SIZE];
    
    // ML-DSAの鍵ペアを生成
    let sk = PrivateKey::keygen(&mut vk_bytes, &mut rng);
    
    // 秘密鍵をバイト配列に変換
    let mut sk_bytes = [0u8; PRIVKEY_SIZE];
    sk.encode(&mut sk_bytes);
    
    DilithiumKeyPair {
        public_key: vk_bytes.to_vec(),
        private_key: sk_bytes.to_vec(),
    }
}

/**
 * メッセージに署名
 * 
 * @param message 署名するメッセージ（バイト配列）
 * @param private_key 秘密鍵（バイト配列）
 * @returns 署名（バイト配列）
 */
#[wasm_bindgen]
pub fn sign(message: &[u8], private_key: &[u8]) -> Vec<u8> {
    // 秘密鍵のサイズをチェック
    if private_key.len() != PRIVKEY_SIZE {
        wasm_bindgen::throw_str(&format!(
            "Invalid private key size: expected {}, got {}",
            PRIVKEY_SIZE,
            private_key.len()
        ));
    }
    
    // 固定サイズ配列に変換
    let mut sk_array = [0u8; PRIVKEY_SIZE];
    sk_array.copy_from_slice(private_key);
    
    // 秘密鍵を復元
    let sk = PrivateKey::decode(&sk_array);
    
    // 乱数生成器を作成
    let mut rng = OsRng;
    
    // 署名のバッファを準備
    let mut sig_bytes = [0u8; SIG_SIZE];
    
    // 署名を生成
    sk.sign(&mut sig_bytes, &mut rng, message);
    
    sig_bytes.to_vec()
}

/**
 * 署名を検証
 * 
 * @param message 元のメッセージ（バイト配列）
 * @param signature 署名（バイト配列）
 * @param public_key 公開鍵（バイト配列）
 * @returns 検証結果（true: 有効、false: 無効）
 */
#[wasm_bindgen]
pub fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    // サイズチェック
    if public_key.len() != PUBKEY_SIZE {
        return false;
    }
    
    if signature.len() != SIG_SIZE {
        return false;
    }
    
    // 固定サイズ配列に変換
    let mut vk_array = [0u8; PUBKEY_SIZE];
    vk_array.copy_from_slice(public_key);
    
    let mut sig_array = [0u8; SIG_SIZE];
    sig_array.copy_from_slice(signature);
    
    // 公開鍵を復元
    let vk = PublicKey::decode(&vk_array);
    
    // 署名を検証
    vk.verify(message, &sig_array).is_ok()
}

// 基本的なテスト関数
#[wasm_bindgen]
pub fn add(a: u32, b: u32) -> u32 {
    a + b
}
