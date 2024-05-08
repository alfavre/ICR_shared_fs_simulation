use super::*;
use file_n_metadata::{EncryptedFile, MetaData};
use sodiumoxide::base64::*;
use sodiumoxide::randombytes::randombytes;
use std::io::{Error, ErrorKind};
use sodiumoxide::crypto::*;


use vault::Vault;

pub struct Server {
    vault: Vault,
    nonce: String,
    id: Option<usize>,
}

impl Server {
    fn new() -> Server {
        Server {
            vault: Vault::default(),
            nonce: String::new(),
            id: None,
        }
    }

    fn calculate_all_possible_answers(&self) -> Vec<String> {
        let all_shared_secret = self.vault.retrieve_all_metadata_shared_secret();
        let mut all_responses = Vec::new();

        for shared_secret in all_shared_secret {
            let mut hash_state = hash::State::new();
            hash_state.update(shared_secret.as_bytes());
            hash_state.update(self.nonce.as_bytes());
            let answer = hash_state.finalize();
            all_responses.push(encode(answer, Variant::UrlSafe));
        }

        all_responses
    }

    pub fn connection() -> Server {
        Server::new()
    }

    pub fn send_challenge(&mut self) -> String {
        let nonce = encode(&randombytes(256), Variant::UrlSafe); // im still scared of birthday clowns
        self.nonce = nonce.clone(); // clone because no time to think
        return nonce;
    }

    pub fn is_answer_accepted(&mut self, answer: String) -> bool {
        match self.verify_challenge_answer(answer) {
            Ok(index) => {
                self.id = Some(index);
                return true;
            }
            Err(_) => return false,
        }
    }

    fn verify_challenge_answer(&self, answer: String) -> Result<usize, Error> {
        let all_possible_answers = self.calculate_all_possible_answers();

        match all_possible_answers.iter().position(|answ| answ == &answer) {
            Some(index) => return Ok(index),
            None => return Err(Error::new(ErrorKind::Other, format!("user doesn't exist"))),
        }
    }

    pub fn ask_for_metadata(&self) -> &MetaData {
        match self
            .vault
            .retrieve_metadata_by_index_value(self.id.unwrap())
        {
            Ok(m) => return m,
            Err(e) => panic!("id is wrong somehow, message from above {}", e),
        };
    }

    pub fn ask_for_specific_file_with_pt_hash(&self, b64_pt_hash: &str) -> &EncryptedFile {
        match self.vault.retrieve_enc_file_by_b64_hash(b64_pt_hash) {
            Ok(enc_file) => enc_file,
            Err(e) => panic!("plain text hash is wrong somehow, message from above {}", e),
        }
    }
}
