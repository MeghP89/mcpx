use anyhow::{Context, Result};
use ort::session::Session;
use ort::value::Tensor;
use std::path::Path;

pub struct Embedder {
    session: Session,
}

impl Embedder {
    pub fn load(model_path: &Path) -> Result<Self> {
        let session = Session::builder()
            .context("Failed to create session builder")?
            .commit_from_file(model_path)
            .map_err(|e| {
                anyhow::anyhow!("Failed to load ONNX model from {:?}: {}", model_path, e)
            })?;
        Ok(Self { session })
    }

    pub fn embed(&mut self, ids: &[i64], attention_mask: &[i64]) -> Result<Vec<f32>> {
        let seq_len = ids.len();
        let token_type_ids: Vec<i64> = vec![0; seq_len];
        let shape = vec![1, seq_len as i64];

        let ids_tensor = Tensor::from_array((shape.clone(), ids.to_vec()))
            .context("Failed to create input_ids tensor")?;
        let mask_tensor = Tensor::from_array((shape.clone(), attention_mask.to_vec()))
            .context("Failed to create attention_mask tensor")?;
        let type_tensor = Tensor::from_array((shape, token_type_ids))
            .context("Failed to create token_type_ids tensor")?;

        let outputs = self.session.run(ort::inputs![
            "input_ids" => ids_tensor,
            "attention_mask" => mask_tensor,
            "token_type_ids" => type_tensor,
        ])?;

        let (shape, data) = outputs[0]
            .try_extract_tensor::<f32>()
            .context("Failed to extract output tensor")?;

        let embedding_dim = shape[2] as usize;

        // Mean pooling: average token embeddings weighted by attention mask
        let mut pooled = vec![0.0f32; embedding_dim];
        let mut mask_sum = 0.0f32;

        for i in 0..seq_len {
            let mask_val = attention_mask[i] as f32;
            mask_sum += mask_val;
            for j in 0..embedding_dim {
                pooled[j] += data[i * embedding_dim + j] * mask_val;
            }
        }

        if mask_sum > 0.0 {
            for val in &mut pooled {
                *val /= mask_sum;
            }
        }

        Ok(pooled)
    }
}
