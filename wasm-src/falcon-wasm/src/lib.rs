use wasm_bindgen::prelude::*;
use pqcrypto_falcon_wasi::falcon512::{keypair, sign, open, PublicKey, SecretKey, SignedMessage};
use pqcrypto_traits_wasi::sign::{PublicKey as PublicKeyTrait, SecretKey as SecretKeyTrait, SignedMessage as SignedMessageTrait};

// wasm-bindgenの初期化
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

// FALCON鍵ペアの型定義
#[wasm_bindgen]
pub struct FalconKeyPair {
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

#[wasm_bindgen]
impl FalconKeyPair {
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
 * FALCON-512鍵ペアを生成
 * FALCON-512はNIST標準化されたFALCONの推奨レベル
 * 
 * @returns 公開鍵と秘密鍵のペア
 */
#[wasm_bindgen]
pub fn generate_keypair() -> Result<FalconKeyPair, JsValue> {
    // FALCON-512の鍵ペアを生成（内部で乱数生成器を使用）
    let (pk, sk) = keypair();
    
    Ok(FalconKeyPair {
        public_key: <PublicKey as PublicKeyTrait>::as_bytes(&pk).to_vec(),
        private_key: <SecretKey as SecretKeyTrait>::as_bytes(&sk).to_vec(),
    })
}

/**
 * メッセージに署名
 * 
 * @param message 署名するメッセージ（バイト配列）
 * @param private_key 秘密鍵（バイト配列）
 * @returns 署名付きメッセージ（バイト配列、メッセージ+署名）
 */
#[wasm_bindgen]
pub fn sign_message(message: &[u8], private_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    // 秘密鍵を復元
    let sk = <SecretKey as SecretKeyTrait>::from_bytes(private_key)
        .map_err(|e| JsValue::from_str(&format!("Invalid secret key: {:?}", e)))?;
    
    // 署名を生成（FALCONは署名付きメッセージを返す）
    let signed_message = sign(message, &sk);
    
    Ok(<SignedMessage as SignedMessageTrait>::as_bytes(&signed_message).to_vec())
}

/**
 * 署名を検証
 * 
 * @param signed_message 署名付きメッセージ（バイト配列、メッセージ+署名）
 * @param public_key 公開鍵（バイト配列）
 * @returns 検証結果（true: 有効、false: 無効）
 */
#[wasm_bindgen]
pub fn verify_signature(signed_message: &[u8], public_key: &[u8]) -> Result<bool, JsValue> {
    // 署名付きメッセージを復元
    let sm = <SignedMessage as SignedMessageTrait>::from_bytes(signed_message)
        .map_err(|e| JsValue::from_str(&format!("Invalid signed message: {:?}", e)))?;
    
    // 公開鍵を復元
    let pk = <PublicKey as PublicKeyTrait>::from_bytes(public_key)
        .map_err(|e| JsValue::from_str(&format!("Invalid public key: {:?}", e)))?;
    
    // 署名を検証（openは検証とメッセージの復元を行う）
    match open(&sm, &pk) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

// 基本的なテスト関数
#[wasm_bindgen]
pub fn add(a: u32, b: u32) -> u32 {
    a + b
}

