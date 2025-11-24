use wasm_bindgen::prelude::*;

mod abe_impl;
use abe_impl::ABEImpl;

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

// ABE関連の型定義
#[wasm_bindgen]
pub struct ABEMasterKey {
    secret: Vec<u8>,
}

#[wasm_bindgen]
impl ABEMasterKey {
    #[wasm_bindgen(constructor)]
    pub fn new() -> ABEMasterKey {
        ABEMasterKey {
            secret: Vec::new(),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> Vec<u8> {
        self.secret.clone()
    }
}

#[wasm_bindgen]
pub struct ABEPublicParams {
    params: Vec<u8>,
}

#[wasm_bindgen]
impl ABEPublicParams {
    #[wasm_bindgen(constructor)]
    pub fn new() -> ABEPublicParams {
        ABEPublicParams {
            params: Vec::new(),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn params(&self) -> Vec<u8> {
        self.params.clone()
    }
}

#[wasm_bindgen]
pub struct ABEPrivateKey {
    key: Vec<u8>,
    attributes: Vec<String>,
}

#[wasm_bindgen]
impl ABEPrivateKey {
    #[wasm_bindgen(constructor)]
    pub fn new() -> ABEPrivateKey {
        ABEPrivateKey {
            key: Vec::new(),
            attributes: Vec::new(),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn key(&self) -> Vec<u8> {
        self.key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn attributes(&self) -> Vec<String> {
        self.attributes.clone()
    }
}

// ABE実装（Miracl Coreを使用）
// CP-ABE (Ciphertext-Policy Attribute-Based Encryption) スキームの実装
#[wasm_bindgen]
pub struct ABE {
    // CP-ABEスキームの実装
    // 今後、Miracl Coreのペアリング演算を使用
}

#[wasm_bindgen]
impl ABE {
    #[wasm_bindgen(constructor)]
    pub fn new() -> ABE {
        ABE {}
    }

    /// マスター鍵ペアを生成
    /// CP-ABEスキームのSetupアルゴリズム
    #[wasm_bindgen]
    pub fn setup(&self) -> Result<JsValue, JsValue> {
        use miracl_core::bn254::ecp::ECP;
        
        // マスター鍵ペアを生成
        let (alpha, p_pub) = ABEImpl::setup();
        
        // マスター秘密鍵をバイト列に変換
        let mut master_key_bytes = vec![0u8; 32];
        alpha.tobytes(&mut master_key_bytes);
        
        // 公開パラメータをバイト列に変換
        let mut public_params_bytes = vec![0u8; 65];
        p_pub.tobytes(&mut public_params_bytes, false);
        
        let master_key = ABEMasterKey {
            secret: master_key_bytes,
        };
        
        let public_params = ABEPublicParams {
            params: public_params_bytes,
        };
        
        // JsValueとして返す
        let result = js_sys::Object::new();
        js_sys::Reflect::set(&result, &"master_key".into(), &master_key.into())?;
        js_sys::Reflect::set(&result, &"public_params".into(), &public_params.into())?;
        
        Ok(result.into())
    }

    /// 属性セットから秘密鍵を生成
    /// CP-ABEスキームのKeyGenアルゴリズム
    #[wasm_bindgen]
    pub fn key_gen(
        &self,
        master_key: &ABEMasterKey,
        attributes: Vec<String>,
    ) -> Result<ABEPrivateKey, JsValue> {
        use miracl_core::bn254::{big::BIG, ecp2::ECP2};
        
        // マスター秘密鍵をBIGに変換
        if master_key.secret.len() != 32 {
            return Err(JsValue::from_str("マスター鍵の長さが不正です"));
        }
        let alpha = BIG::frombytes(&master_key.secret);
        
        // 秘密鍵コンポーネントを生成
        let key_components = ABEImpl::key_gen(&alpha, &attributes);
        
        // 鍵コンポーネントをバイト列に変換
        let mut key_bytes = Vec::new();
        for key_comp in &key_components {
            let mut comp_bytes = vec![0u8; 130];
            key_comp.tobytes(&mut comp_bytes, false);
            key_bytes.extend_from_slice(&comp_bytes);
        }
        
        Ok(ABEPrivateKey {
            key: key_bytes,
            attributes,
        })
    }

    /// メッセージを暗号化
    /// CP-ABEスキームのEncryptアルゴリズム
    /// 注意: 簡易実装。ポリシーは属性のリストとして扱う
    #[wasm_bindgen]
    pub fn encrypt(
        &self,
        public_params: &ABEPublicParams,
        policy: &str,
        message: &[u8],
    ) -> Result<Vec<u8>, JsValue> {
        use miracl_core::bn254::ecp::ECP;
        
        // 公開パラメータをECPに変換
        if public_params.params.len() < 65 {
            return Err(JsValue::from_str("公開パラメータの長さが不正です"));
        }
        let p_pub = ECP::frombytes(&public_params.params);
        
        // ポリシーから属性を抽出（簡易実装: カンマ区切り）
        let attributes: Vec<String> = policy
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        
        if attributes.is_empty() {
            return Err(JsValue::from_str("ポリシーには少なくとも1つの属性が必要です"));
        }
        
        // メッセージを暗号化
        let (c0, v, c_attrs) = ABEImpl::encrypt(&p_pub, &attributes, message);
        
        // 暗号文をバイト列に変換（num_attrs (1バイト) || C0 (65バイト) || V (可変長) || C_attrsの形式）
        let num_attrs = c_attrs.len();
        if num_attrs > 255 {
            return Err(JsValue::from_str("属性が多すぎます（最大255個）"));
        }
        
        let mut ciphertext = vec![num_attrs as u8]; // 属性数を先頭に保存
        
        // C0を追加
        let mut c0_bytes = vec![0u8; 65];
        c0.tobytes(&mut c0_bytes, false);
        ciphertext.extend_from_slice(&c0_bytes);
        
        // Vを追加
        ciphertext.extend_from_slice(&v);
        
        // 属性ごとの暗号文コンポーネントを追加
        for c_attr in &c_attrs {
            let mut attr_bytes = vec![0u8; 130];
            c_attr.tobytes(&mut attr_bytes, false);
            ciphertext.extend_from_slice(&attr_bytes);
        }
        
        Ok(ciphertext)
    }

    /// 暗号文を復号化
    /// CP-ABEスキームのDecryptアルゴリズム
    /// 注意: 簡易実装。実際のCP-ABEでは、ポリシー満足性のチェックが必要
    #[wasm_bindgen]
    pub fn decrypt(
        &self,
        private_key: &ABEPrivateKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, JsValue> {
        use miracl_core::bn254::{ecp::ECP, ecp2::ECP2};
        
        if ciphertext.len() < 66 {
            return Err(JsValue::from_str("暗号文が短すぎます"));
        }
        
        // 暗号文を解析（num_attrs (1バイト) || C0 (65バイト) || V (可変長) || C_attrsの形式）
        let ciphertext_num_attrs = ciphertext[0] as usize;
        let c0_start = 1;
        let c0_end = c0_start + 65;
        
        if ciphertext.len() < c0_end {
            return Err(JsValue::from_str("暗号文にC0コンポーネントがありません"));
        }
        
        let c0 = ECP::frombytes(&ciphertext[c0_start..c0_end]);
        
        // 暗号化時の属性数と秘密鍵の属性数を比較
        let key_num_attrs = private_key.attributes.len();
        
        if ciphertext_num_attrs != key_num_attrs {
            return Err(JsValue::from_str(&format!(
                "属性が一致しません: 暗号文は{}個の属性を必要としますが、秘密鍵は{}個の属性を持っています。暗号化時に使用した属性と鍵生成時に使用した属性が一致する必要があります。",
                ciphertext_num_attrs,
                key_num_attrs
            )));
        }
        
        let attr_component_size = 130;
        let expected_min_size = c0_end + ciphertext_num_attrs * attr_component_size;
        
        if ciphertext.len() < expected_min_size {
            return Err(JsValue::from_str(&format!(
                "暗号文が不正です: 最低{}バイト必要ですが、{}バイトしかありません",
                expected_min_size,
                ciphertext.len()
            )));
        }
        
        // Vを抽出（C0の後、属性コンポーネントの前）
        let v_start = c0_end;
        let v_end = ciphertext.len() - (ciphertext_num_attrs * attr_component_size);
        
        if v_end <= v_start {
            return Err(JsValue::from_str("暗号文のVコンポーネントが空または不正です"));
        }
        
        let v = &ciphertext[v_start..v_end];
        
        // 属性コンポーネントを抽出
        let mut c_attrs = Vec::new();
        for i in 0..ciphertext_num_attrs {
            let start = v_end + (i * attr_component_size);
            let end = start + attr_component_size;
            if end > ciphertext.len() {
                return Err(JsValue::from_str("暗号文の属性コンポーネントが範囲外です"));
            }
            let c_attr = ECP2::frombytes(&ciphertext[start..end]);
            c_attrs.push(c_attr);
        }
        
        // 秘密鍵コンポーネントを抽出
        let mut key_components = Vec::new();
        let key_bytes = &private_key.key;
        let key_component_size = 130;
        
        if key_bytes.len() < key_num_attrs * key_component_size {
            return Err(JsValue::from_str("秘密鍵に鍵コンポーネントが不足しています"));
        }
        
        for i in 0..key_num_attrs {
            let start = i * key_component_size;
            let end = start + key_component_size;
            if end > key_bytes.len() {
                return Err(JsValue::from_str("秘密鍵の鍵コンポーネントが範囲外です"));
            }
            let key_comp = ECP2::frombytes(&key_bytes[start..end]);
            key_components.push(key_comp);
        }
        
        // 暗号文を復号化
        let message = ABEImpl::decrypt(&key_components, &c0, v, &c_attrs);
        
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

