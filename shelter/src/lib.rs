pub mod error;
pub mod http;

use std::collections::BTreeMap;

use base64::Engine;

#[derive(Clone, Debug)]
pub struct ExfiltratedFilePortion {
    pub file_name: String,
    pub index: usize,
    pub file_content: Vec<u8>,
    pub is_last_portion: bool,
}

#[derive(Clone, Debug)]
pub struct ExfiltratedFile {
    pub name: String,
    pub portions: BTreeMap<usize, Vec<u8>>,
}

impl ExfiltratedFile {
    pub fn new(name: String) -> Self {
        Self {
            name,
            portions: BTreeMap::new(),
        }
    }

    pub fn add_portion(&mut self, file_portion: ExfiltratedFilePortion) {
        self.portions
            .insert(file_portion.index, file_portion.file_content);
    }

    pub fn get_file_contents(&self) -> Vec<u8> {
        self.portions
            .values()
            .filter_map(|chunk| hex::decode(chunk).ok())
            .filter_map(|b64_chunk| base64::prelude::BASE64_STANDARD.decode(b64_chunk).ok())
            .flatten()
            .collect()
    }
}

impl ExfiltratedFilePortion {
    pub fn new(
        file_name: String,
        index: usize,
        file_content: Vec<u8>,
        is_last_portion: bool,
    ) -> Self {
        Self {
            file_content,
            index,
            file_name,
            is_last_portion,
        }
    }
}

fn is_not_payload_separator(separator: u8) -> impl Fn(u8) -> Option<u8> {
    move |byte| byte.ne(&separator).then_some(byte)
}

impl TryFrom<String> for ExfiltratedFilePortion {
    type Error = crate::error::app::AppError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let mut payload_iter = base64::prelude::BASE64_STANDARD
            .decode(hex::decode(value)?)?
            .into_iter();

        let file_name = String::from_utf8(
            payload_iter
                .by_ref()
                .map_while(is_not_payload_separator(':' as u8))
                .collect::<Vec<u8>>(),
        )?;

        let index = String::from_utf8(
            payload_iter
                .by_ref()
                .map_while(is_not_payload_separator(':' as u8))
                .collect::<Vec<u8>>(),
        )?
        .parse::<usize>()?;

        let file_content = payload_iter
            .by_ref()
            .map_while(is_not_payload_separator(':' as u8))
            .collect::<Vec<u8>>();

        let last_payload = payload_iter
            .by_ref()
            .map_while(is_not_payload_separator(':' as u8))
            .collect::<Vec<u8>>();

        Ok(Self::new(
            file_name,
            index,
            file_content,
            !last_payload.is_empty(),
        ))
    }
}
