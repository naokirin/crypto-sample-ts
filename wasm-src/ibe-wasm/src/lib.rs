use wasm_bindgen::prelude::*;

mod ibe_impl;
use ibe_impl::IBEImpl;

// wasm-bindgenの初期化
#[wasm_bindgen(start)]
pub fn init() {
    // コンソールエラーハンドリングの設定
    console_error_panic_hook::set_once();
}

// 基本的なテスト関数
#[wasm_bindgen]
pub fn add(a: u32, b: u32) -> u32 {
    a + b
}

// IBE関連の型定義
#[wasm_bindgen]
pub struct IBEMasterKey {
    secret: Vec<u8>,
}

#[wasm_bindgen]
impl IBEMasterKey {
    #[wasm_bindgen(constructor)]
    pub fn new() -> IBEMasterKey {
        IBEMasterKey {
            secret: Vec::new(),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> Vec<u8> {
        self.secret.clone()
    }
}

#[wasm_bindgen]
pub struct IBEPublicParams {
    params: Vec<u8>,
}

#[wasm_bindgen]
impl IBEPublicParams {
    #[wasm_bindgen(constructor)]
    pub fn new() -> IBEPublicParams {
        IBEPublicParams {
            params: Vec::new(),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn params(&self) -> Vec<u8> {
        self.params.clone()
    }
}

#[wasm_bindgen]
pub struct IBEPrivateKey {
    key: Vec<u8>,
}

#[wasm_bindgen]
impl IBEPrivateKey {
    #[wasm_bindgen(constructor)]
    pub fn new() -> IBEPrivateKey {
        IBEPrivateKey {
            key: Vec::new(),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn key(&self) -> Vec<u8> {
        self.key.clone()
    }
}

// IBE実装（Miracl Coreを使用）
// 注意: 現在は基本的な構造のみ。Miracl CoreのAPIを確認しながら段階的に実装を進めます。
#[wasm_bindgen]
pub struct IBE {
    // Boneh-Franklin IBEスキームの実装
    // 今後、Miracl Coreのペアリング演算を使用
}

#[wasm_bindgen]
impl IBE {
    #[wasm_bindgen(constructor)]
    pub fn new() -> IBE {
        IBE {}
    }

    /// マスター鍵ペアを生成
    /// Boneh-Franklin IBEスキームのSetupアルゴリズム
    #[wasm_bindgen]
    pub fn setup(&self) -> Result<JsValue, JsValue> {
        use miracl_core::bn254::ecp::ECP;
        
        // マスター鍵ペアを生成
        let (s, p_pub) = IBEImpl::setup();
        
        // マスター秘密鍵をバイト列に変換
        let mut master_key_bytes = vec![0u8; 32];
        s.tobytes(&mut master_key_bytes);
        
        // 公開パラメータをバイト列に変換
        let mut public_params_bytes = vec![0u8; 65];
        p_pub.tobytes(&mut public_params_bytes, false);
        
        let master_key = IBEMasterKey {
            secret: master_key_bytes,
        };
        
        let public_params = IBEPublicParams {
            params: public_params_bytes,
        };
        
        // JsValueとして返す
        let result = js_sys::Object::new();
        js_sys::Reflect::set(&result, &"master_key".into(), &master_key.into())?;
        js_sys::Reflect::set(&result, &"public_params".into(), &public_params.into())?;
        
        Ok(result.into())
    }

    /// アイデンティティから秘密鍵を抽出
    /// Boneh-Franklin IBEスキームのExtractアルゴリズム
    #[wasm_bindgen]
    pub fn extract(
        &self,
        master_key: &IBEMasterKey,
        identity: &str,
    ) -> Result<IBEPrivateKey, JsValue> {
        use miracl_core::bn254::{big::BIG, ecp2::ECP2};
        
        // マスター秘密鍵をBIGに変換
        if master_key.secret.len() != 32 {
            return Err(JsValue::from_str("Invalid master key length"));
        }
        let s = BIG::frombytes(&master_key.secret);
        
        // 秘密鍵を抽出
        let d_id = IBEImpl::extract(&s, identity);
        
        // 秘密鍵をバイト列に変換
        let mut key_bytes = vec![0u8; 130];
        d_id.tobytes(&mut key_bytes, false);
        
        Ok(IBEPrivateKey {
            key: key_bytes,
        })
    }

    /// メッセージを暗号化
    /// Boneh-Franklin IBEスキームのEncryptアルゴリズム
    #[wasm_bindgen]
    pub fn encrypt(
        &self,
        public_params: &IBEPublicParams,
        identity: &str,
        message: &[u8],
    ) -> Result<Vec<u8>, JsValue> {
        use miracl_core::bn254::ecp::ECP;
        
        // 公開パラメータをECPに変換
        if public_params.params.len() < 65 {
            return Err(JsValue::from_str("Invalid public params length"));
        }
        let p_pub = ECP::frombytes(&public_params.params);
        
        // メッセージを暗号化
        let (u, v) = IBEImpl::encrypt(&p_pub, identity, message);
        
        // 暗号文をバイト列に変換（U || Vの形式）
        let mut u_bytes = vec![0u8; 65];
        u.tobytes(&mut u_bytes, false);
        
        let mut ciphertext = u_bytes;
        ciphertext.extend_from_slice(&v);
        
        Ok(ciphertext)
    }

    /// 暗号文を復号化
    /// Boneh-Franklin IBEスキームのDecryptアルゴリズム
    #[wasm_bindgen]
    pub fn decrypt(
        &self,
        private_key: &IBEPrivateKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, JsValue> {
        use miracl_core::bn254::{ecp::ECP, ecp2::ECP2};
        
        if ciphertext.len() < 65 {
            return Err(JsValue::from_str("Invalid ciphertext length"));
        }
        
        // 暗号文を解析（U || Vの形式）
        let u = ECP::frombytes(&ciphertext[..65]);
        let v = &ciphertext[65..];
        
        // 秘密鍵をECP2に変換
        if private_key.key.len() < 130 {
            return Err(JsValue::from_str("Invalid private key length"));
        }
        let d_id = ECP2::frombytes(&private_key.key);
        
        // 暗号文を復号化
        let message = IBEImpl::decrypt(&d_id, &u, v);
        
        Ok(message)
    }
}

// コンソールログ用のマクロ（今後使用予定）
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[allow(unused_macros)]
macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}
