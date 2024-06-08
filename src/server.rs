use super::*;
use file_n_metadata::{UserEncryptedFolder, UserMetaData,UserEncryptedFile};
use sodiumoxide::base64::*;
use sodiumoxide::crypto;
use sodiumoxide::crypto::*;
use sodiumoxide::randombytes::randombytes;
use std::io::{Error, ErrorKind};

use vault::Vault;

pub struct Server {
    vault: Vault,
    challenge_secret: String,
    client_pk: Option<box_::PublicKey>,
    id: Option<usize>,
    server_pk:box_::PublicKey,
    server_sk:box_::SecretKey
}

impl Server {
    fn new() -> Server {
        let (pk,sk) = crypto::box_::gen_keypair();
        Server {
            vault: Vault::default(),
            challenge_secret: String::new(),
            client_pk: None,
            id: None,
            server_pk:pk,
            server_sk:sk,
        }
    }
    /*
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
    }*/

    pub fn connection() -> Server {
        Server::new()
    }

    pub fn send_challenge(&mut self, username:String) -> (Vec<u8>,box_::PublicKey, box_::Nonce,String) {
        let real_nonce = box_::gen_nonce();
        self.challenge_secret = encode(&randombytes(256), Variant::UrlSafe); // im still scared of birthday clowns
        let encoded_pk = self.vault.retrieve_public_key_for(username.clone()).expect("Failed to retrieve public key");
        self.client_pk = box_::PublicKey::from_slice(&decode(encoded_pk,Variant::UrlSafe).unwrap());
        
        let enc_challenge = crypto::box_::seal(self.challenge_secret.as_bytes(), &real_nonce, &self.client_pk.unwrap(), &self.server_sk);

        return (enc_challenge,self.server_pk,real_nonce,self.vault.retrieve_salt_for(username.clone()).expect("Failed to retrieve salt"));
    }

    /*
        pub fn is_answer_accepted(&mut self, answer: String) -> bool {
        match self.verify_challenge_answer(answer) {
            Ok(index) => {
                self.id = Some(index);
                return true;
            }
            Err(_) => return false,
        }
    }*/
/*
    fn verify_challenge_answer(&self, answer: String) -> Result<usize, Error> {
        let all_possible_answers = self.calculate_all_possible_answers();

        match all_possible_answers.iter().position(|answ| answ == &answer) {
            Some(index) => return Ok(index),
            None => return Err(Error::new(ErrorKind::Other, format!("user doesn't exist"))),
        }
    }
*/
    pub fn ask_for_metadata(&self) -> &UserMetaData {
        match self
            .vault
            .retrieve_metadata_by_index_value(self.id.unwrap())
        {
            Ok(m) => return m,
            Err(e) => panic!("id is wrong somehow, message from above {}", e),
        };
    }

    pub fn ask_for_specific_file_with_pt_hash(&self, b64_pt_hash: &str) -> &UserEncryptedFile {
        match self.vault.retrieve_enc_file_by_b64_hash(b64_pt_hash) {
            Ok(enc_file) => enc_file,
            Err(e) => panic!("plain text hash is wrong somehow, message from above {}", e),
        }
    }
}
