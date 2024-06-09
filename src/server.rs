use super::*;
use file_n_metadata::{UserEncryptedFile, UserEncryptedFolder, UserMetaData};
use sodiumoxide::base64::*;
use sodiumoxide::crypto;
use sodiumoxide::crypto::*;
use sodiumoxide::randombytes::randombytes;

use vault::Vault;

pub struct Server {
    vault: Vault,
    challenge_secret: String,
    client_pk: Option<box_::PublicKey>,
    id: Option<usize>,
    server_pk: box_::PublicKey,
    server_sk: box_::SecretKey,
}

impl Server {
    fn new() -> Server {
        let (pk, sk) = crypto::box_::gen_keypair();
        Server {
            vault: Vault::default(),
            challenge_secret: String::new(),
            client_pk: None,
            id: None,
            server_pk: pk,
            server_sk: sk,
        }
    }

    pub fn connection() -> Server {
        Server::new()
    }

    /**
     * Challenge is simply a random nonce encrypted with user public key
     * I tried to stop data leak but could not
     * If the user is not in DB, server will still do the encryption but with its own private key(to avoid a side channel attack)
     * If the user is not in DB, a random salt is given instead of a user salt.
     * Problem, If user exists, we always give the same salt so side channel attack is still possible
     * possible fix: genereate the salt of missing user using missing username as a seed somehow
     */
    pub fn send_challenge(
        &mut self,
        username: String,
    ) -> (Vec<u8>, box_::PublicKey, box_::Nonce, String) {
        let real_nonce = box_::gen_nonce();
        let client_public_key;

        match self.vault.retrieve_public_key_for(username.as_str()) {
            Ok(key) => client_public_key = key,
            Err(e) => client_public_key = encode(self.server_pk, Variant::UrlSafe), // in case someone wants to deduce if user exists in db
        }

        self.challenge_secret = encode(&randombytes(256), Variant::UrlSafe); // im still scared of birthday clowns
        let encoded_pk = client_public_key;
        self.client_pk =
            box_::PublicKey::from_slice(&decode(encoded_pk, Variant::UrlSafe).unwrap());

        let enc_challenge = crypto::box_::seal(
            self.challenge_secret.as_bytes(),
            &real_nonce,
            &self.client_pk.unwrap(),
            &self.server_sk,
        );

        let client_salt;

        match self.vault.retrieve_salt_for(username.as_str()) {
            Ok(salt) => client_salt = salt,
            Err(_) => client_salt = encode(pwhash::gen_salt(), Variant::UrlSafe), // not good enough, explain in report
        }

        return (enc_challenge, self.server_pk, real_nonce, client_salt);
    }

    pub fn is_answer_accepted(&self, answer: String) -> bool {
        return answer.as_str() == self.challenge_secret.as_str();
    }

    pub fn ask_for_public_key(&self, username: &str) -> box_::PublicKey {
        match self.vault.retrieve_public_key_for(username) {
            Ok(pk) => {
                return box_::PublicKey::from_slice(&decode(pk, Variant::UrlSafe).unwrap()).unwrap()
            }
            Err(e) => panic!("Something went wrong while fetching pk: {}", e),
        };
    }

    pub fn ask_for_metadata(&self, username: &str) -> &UserMetaData {
        match self.vault.retrieve_metadata_for(username) {
            Ok(m) => return m,
            Err(e) => panic!("Something went wrong while fetching metadata: {}", e),
        };
    }

    pub fn ask_for_folder(&self, b64_folder_name_hash: &str) -> &UserEncryptedFolder {
        match self
            .vault
            .retrieve_enc_folder_by_b64_hash(b64_folder_name_hash)
        {
            Ok(m) => return m,
            Err(e) => panic!("Something went wrong while fetching folder: {}", e),
        };
    }

    pub fn ask_for_file(&self, b64_file_name_hash: &str) -> &UserEncryptedFile {
        match self.vault.retrieve_enc_file_by_b64_hash(b64_file_name_hash) {
            Ok(m) => return m,
            Err(e) => panic!("Something went wrong while fetching file: {}", e),
        };
    }
}
