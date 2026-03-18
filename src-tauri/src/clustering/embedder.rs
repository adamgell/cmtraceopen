use ndarray::Array2;
use ort::{session::Session, value::Value};
use rayon::prelude::*;
use std::path::Path;
use tokenizers::Tokenizer;

/// Sentence embedding engine using all-MiniLM-L6-v2 ONNX model.
pub struct Embedder {
    session: Session,
    tokenizer: Tokenizer,
}

/// Embedding dimension for all-MiniLM-L6-v2.
pub const EMBEDDING_DIM: usize = 384;
const MAX_SEQ_LEN: usize = 128; // MiniLM max is 256, but 128 is sufficient for log lines

impl Embedder {
    /// Creates a new embedder from model and tokenizer file paths.
    pub fn new(model_path: &Path, tokenizer_path: &Path) -> Result<Self, String> {
        let session = Session::builder()
            .map_err(|e| format!("Failed to create ONNX session builder: {}", e))?
            .with_intra_threads(4)
            .map_err(|e| format!("Failed to set thread count: {}", e))?
            .commit_from_file(model_path)
            .map_err(|e| format!("Failed to load ONNX model: {}", e))?;

        let tokenizer = Tokenizer::from_file(tokenizer_path)
            .map_err(|e| format!("Failed to load tokenizer: {}", e))?;

        Ok(Self { session, tokenizer })
    }

    /// Embeds a batch of texts, returning normalized 384-dim vectors.
    pub fn embed_batch(&mut self, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }

        let mut all_embeddings = Vec::with_capacity(texts.len());

        // Process in sub-batches to limit memory usage
        let batch_size = 64;
        for batch in texts.chunks(batch_size) {
            let batch_embeddings = self.embed_sub_batch(batch)?;
            all_embeddings.extend(batch_embeddings);
        }

        Ok(all_embeddings)
    }

    fn embed_sub_batch(&mut self, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
        let encodings = self
            .tokenizer
            .encode_batch(texts.to_vec(), true)
            .map_err(|e| format!("Tokenization error: {}", e))?;

        let batch_len = encodings.len();

        // Determine actual max length in this batch (clamped to MAX_SEQ_LEN)
        let max_len = encodings
            .iter()
            .map(|enc| enc.get_ids().len().min(MAX_SEQ_LEN))
            .max()
            .unwrap_or(1);

        // Build padded input tensors
        let mut input_ids = vec![0i64; batch_len * max_len];
        let mut attention_mask = vec![0i64; batch_len * max_len];
        let mut token_type_ids = vec![0i64; batch_len * max_len];

        for (i, encoding) in encodings.iter().enumerate() {
            let ids = encoding.get_ids();
            let mask = encoding.get_attention_mask();
            let seq_len = ids.len().min(max_len);

            for j in 0..seq_len {
                input_ids[i * max_len + j] = ids[j] as i64;
                attention_mask[i * max_len + j] = mask[j] as i64;
                // token_type_ids stays 0
            }
        }

        let input_ids_array =
            Array2::from_shape_vec((batch_len, max_len), input_ids)
                .map_err(|e| format!("Array shape error: {}", e))?;
        let attention_mask_array =
            Array2::from_shape_vec((batch_len, max_len), attention_mask)
                .map_err(|e| format!("Array shape error: {}", e))?;
        let token_type_ids_array =
            Array2::from_shape_vec((batch_len, max_len), token_type_ids)
                .map_err(|e| format!("Array shape error: {}", e))?;

        let input_ids_value = Value::from_array(input_ids_array)
            .map_err(|e| format!("Input tensor error: {}", e))?;
        let attention_mask_value = Value::from_array(attention_mask_array)
            .map_err(|e| format!("Attention mask tensor error: {}", e))?;
        let token_type_ids_value = Value::from_array(token_type_ids_array)
            .map_err(|e| format!("Token type ids tensor error: {}", e))?;

        let outputs = self
            .session
            .run(ort::inputs![
                "input_ids" => input_ids_value,
                "attention_mask" => attention_mask_value,
                "token_type_ids" => token_type_ids_value,
            ])
            .map_err(|e| format!("ONNX inference error: {}", e))?;

        // Extract last_hidden_state: (batch, seq_len, hidden_dim)
        let output_view = outputs[0]
            .try_extract_array::<f32>()
            .map_err(|e| format!("Output extraction error: {}", e))?;

        let output_shape = output_view.shape();
        let hidden_dim = output_shape[2];

        // Mean pooling + L2 normalization parallelized across batch items
        let embeddings: Vec<Vec<f32>> = (0..batch_len)
            .into_par_iter()
            .map(|i| {
                let mut pooled = vec![0.0f32; hidden_dim];
                let mask_sum: f32 = (0..max_len)
                    .map(|j| {
                        let mask_val = if j < encodings[i].get_attention_mask().len() {
                            encodings[i].get_attention_mask()[j] as f32
                        } else {
                            0.0
                        };
                        for k in 0..hidden_dim {
                            pooled[k] += output_view[[i, j, k]] * mask_val;
                        }
                        mask_val
                    })
                    .sum();

                if mask_sum > 0.0 {
                    for val in &mut pooled {
                        *val /= mask_sum;
                    }
                }

                // L2 normalize
                let norm: f32 = pooled.iter().map(|v| v * v).sum::<f32>().sqrt();
                if norm > 0.0 {
                    for val in &mut pooled {
                        *val /= norm;
                    }
                }

                pooled
            })
            .collect();

        Ok(embeddings)
    }
}

/// Cosine similarity between two L2-normalized vectors (equals dot product).
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}
