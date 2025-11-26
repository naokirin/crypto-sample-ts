use wasm_bindgen::prelude::*;
use falcon_rust::falcon512::{keygen, sign, verify, PublicKey, SecretKey};
use rand::rngs::OsRng;
use rand::RngCore;

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
 * 
 * @returns 公開鍵と秘密鍵のペア
 */
#[wasm_bindgen]
pub fn generate_keypair() -> Result<FalconKeyPair, JsValue> {
    // 乱数生成器を作成
    let mut rng = OsRng;
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    
    // FALCON-512の鍵ペアを生成（返り値は(SecretKey, PublicKey)の順）
    let (sk, pk) = keygen(seed);
    
    Ok(FalconKeyPair {
        public_key: pk.to_bytes(),
        private_key: sk.to_bytes(),
    })
}

/**
 * メッセージに署名
 * 
 * @param message 署名するメッセージ（バイト配列）
 * @param private_key 秘密鍵（バイト配列）
 * @returns 署名（バイト配列）
 */
#[wasm_bindgen]
pub fn sign_message(message: &[u8], private_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    // 秘密鍵を復元
    let sk = SecretKey::from_bytes(private_key)
        .map_err(|e| JsValue::from_str(&format!("Invalid secret key: {:?}", e)))?;
    
    // 署名を生成（signは直接Signatureを返す）
    let signature = sign(message, &sk);
    
    Ok(signature.to_bytes())
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
pub fn verify_signature(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, JsValue> {
    use falcon_rust::falcon512::Signature;
    
    // 公開鍵を復元
    let pk = PublicKey::from_bytes(public_key)
        .map_err(|e| JsValue::from_str(&format!("Invalid public key: {:?}", e)))?;
    
    // 署名を復元
    let sig = Signature::from_bytes(signature)
        .map_err(|e| JsValue::from_str(&format!("Invalid signature: {:?}", e)))?;
    
    // 署名を検証（verifyはboolを返す）
    Ok(verify(message, &sig, &pk))
}

// 基本的なテスト関数
#[wasm_bindgen]
pub fn add(a: u32, b: u32) -> u32 {
    a + b
}
