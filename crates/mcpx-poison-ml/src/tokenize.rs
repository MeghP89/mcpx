use anyhow::Result;
use std::path::Path;

pub struct TokenOutput {
    pub ids: Vec<i64>,
    pub attention_mask: Vec<i64>,
}

pub struct Tokenizer {
    inner: tokenizers::Tokenizer,
}

impl Tokenizer {
    pub fn load(path: &Path) -> Result<Self> {
        let inner = tokenizers::Tokenizer::from_file(path)
            .map_err(|e| anyhow::anyhow!("Failed to load tokenizer from {:?}: {}", path, e))?;
        Ok(Self { inner })
    }

    pub fn encode(&self, text: &str) -> Result<TokenOutput> {
        let encoding = self
            .inner
            .encode(text, true)
            .map_err(|e| anyhow::anyhow!("Failed to encode text: {}", e))?;

        let ids: Vec<i64> = encoding.get_ids().iter().map(|&id| id as i64).collect();
        let attention_mask: Vec<i64> = encoding
            .get_attention_mask()
            .iter()
            .map(|&mask| mask as i64)
            .collect();

        Ok(TokenOutput {
            ids,
            attention_mask,
        })
    }
}
