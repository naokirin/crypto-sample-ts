use wasm_bindgen::prelude::*;
use pqcrypto_std::mlkem::{keygen, EncapsKey, DecapsKey};
use rand::rngs::OsRng;

// wasm-bindgenの初期化
#[wasm_bindgen(start)]
pub fn init() {
    // コンソールエラーハンドリングの設定
    console_error_panic_hook::set_once();
}

// Kyber鍵ペアの型定義
#[wasm_bindgen]
pub struct KyberKeyPair {
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

#[wasm_bindgen]
impl KyberKeyPair {
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn private_key(&self) -> Vec<u8> {
        self.private_key.clone()
    }
}

// カプセル化結果の型定義
#[wasm_bindgen]
pub struct KyberEncapsulation {
    ciphertext: Vec<u8>,
    shared_secret: Vec<u8>,
}

#[wasm_bindgen]
impl KyberEncapsulation {
    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn shared_secret(&self) -> Vec<u8> {
        self.shared_secret.clone()
    }
}

/**
 * CRYSTALS-Kyber鍵ペアを生成
 * ML-KEMを使用（NIST標準化されたKyber）
 * 
 * @returns 公開鍵と秘密鍵のペア
 */
#[wasm_bindgen]
pub fn generate_keypair() -> KyberKeyPair {
    // 乱数生成器を作成
    let mut rng = OsRng;
    
    // ML-KEMの鍵ペアを生成
    let (ek, dk) = keygen(&mut rng);
    
    // バイト配列に変換
    let mut pk_bytes = [0u8; EncapsKey::BYTE_SIZE];
    ek.to_bytes(&mut pk_bytes);
    
    let mut sk_bytes = [0u8; DecapsKey::BYTE_SIZE];
    dk.to_bytes(&mut sk_bytes, &ek);
    
    KyberKeyPair {
        public_key: pk_bytes.to_vec(),
        private_key: sk_bytes.to_vec(),
    }
}

/**
 * 鍵カプセル化（Encapsulation）
 * 公開鍵を使用して共有秘密を生成し、カプセル化する
 * 
 * @param public_key 公開鍵（バイト配列、固定サイズ）
 * @returns 暗号文と共有秘密
 */
#[wasm_bindgen]
pub fn encapsulate(public_key: &[u8]) -> KyberEncapsulation {
    // 公開鍵のサイズをチェック
    if public_key.len() != EncapsKey::BYTE_SIZE {
        wasm_bindgen::throw_str(&format!(
            "Invalid public key size: expected {}, got {}",
            EncapsKey::BYTE_SIZE,
            public_key.len()
        ));
    }
    
    // 固定サイズ配列に変換
    let mut pk_array = [0u8; EncapsKey::BYTE_SIZE];
    pk_array.copy_from_slice(public_key);
    
    // 公開鍵を復元（from_bytesはResultを返さない）
    let ek = EncapsKey::from_bytes(&pk_array);
    
    // 乱数生成器を作成
    let mut rng = OsRng;
    
    // カプセル化を実行（共有秘密と暗号文のバッファを準備）
    let mut ss_bytes = [0u8; 32]; // 共有秘密は32バイト
    let mut ct_bytes = [0u8; EncapsKey::CIPHERTEXT_SIZE];
    
    // encapsの引数順序: (暗号文, 共有秘密, 乱数生成器)
    ek.encaps(&mut ct_bytes, &mut ss_bytes, &mut rng);
    
    KyberEncapsulation {
        ciphertext: ct_bytes.to_vec(),
        shared_secret: ss_bytes.to_vec(),
    }
}

/**
 * 鍵デカプセル化（Decapsulation）
 * 秘密鍵と暗号文を使用して共有秘密を復元する
 * 
 * @param ciphertext 暗号文（バイト配列、固定サイズ）
 * @param private_key 秘密鍵（バイト配列、固定サイズ）
 * @param public_key 公開鍵（秘密鍵の復元に必要）
 * @returns 共有秘密
 */
#[wasm_bindgen]
pub fn decapsulate(ciphertext: &[u8], private_key: &[u8], public_key: &[u8]) -> Vec<u8> {
    // サイズチェック
    if ciphertext.len() != EncapsKey::CIPHERTEXT_SIZE {
        wasm_bindgen::throw_str(&format!(
            "Invalid ciphertext size: expected {}, got {}",
            EncapsKey::CIPHERTEXT_SIZE,
            ciphertext.len()
        ));
    }
    
    if private_key.len() != DecapsKey::BYTE_SIZE {
        wasm_bindgen::throw_str(&format!(
            "Invalid secret key size: expected {}, got {}",
            DecapsKey::BYTE_SIZE,
            private_key.len()
        ));
    }
    
    if public_key.len() != EncapsKey::BYTE_SIZE {
        wasm_bindgen::throw_str(&format!(
            "Invalid public key size: expected {}, got {}",
            EncapsKey::BYTE_SIZE,
            public_key.len()
        ));
    }
    
    // 固定サイズ配列に変換
    let mut ct_array = [0u8; EncapsKey::CIPHERTEXT_SIZE];
    ct_array.copy_from_slice(ciphertext);
    
    let mut sk_array = [0u8; DecapsKey::BYTE_SIZE];
    sk_array.copy_from_slice(private_key);
    
    let mut pk_array = [0u8; EncapsKey::BYTE_SIZE];
    pk_array.copy_from_slice(public_key);
    
    // 鍵を復元（from_bytesはResultを返さない）
    let ek = EncapsKey::from_bytes(&pk_array);
    let dk = DecapsKey::from_bytes(&sk_array);
    
    // 共有秘密のバッファを準備
    let mut ss_bytes = [0u8; 32]; // 共有秘密は32バイト
    
    // デカプセル化を実行（引数順序: 共有秘密, 公開鍵, 暗号文）
    dk.decaps(&mut ss_bytes, &ek, &ct_array);
    
    ss_bytes.to_vec()
}

// 基本的なテスト関数
#[wasm_bindgen]
pub fn add(a: u32, b: u32) -> u32 {
    a + b
}
