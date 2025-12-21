use crate::nodes::{file_chunk::FileChunkNode, Node};

pub fn build_chunk_nodes(
    ref_root_identifier: std::rc::Rc<[u8; 4]>,
    bytes: Vec<u8>,
    chunks: usize,
) -> crate::error::Result<Vec<Node>> {
    let mut nodes = Vec::new();
    nodes.extend(
        bytes
            .chunks(bytes.len().div_ceil(chunks))
            .enumerate()
            .map(|(index, chunk)| {
                Node::FileChunk(FileChunkNode::new(
                    std::rc::Rc::clone(&ref_root_identifier),
                    index + 1,
                    chunk.to_vec(),
                ))
            }),
    );

    if let Some(Node::FileChunk(chunk_node)) = nodes.last_mut() {
        chunk_node.set_last_chunk();
    };

    Ok(nodes)
}

pub fn encode_file_chunks_to_hex_b64(nodes: Vec<Node>) -> Vec<String> {
    nodes
        .into_iter()
        .map(|node| crate::encoders::encode_b64_hex(node.to_string()))
        .collect()
}
