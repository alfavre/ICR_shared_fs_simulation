use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedFile {
    pub pt_filename_hash: String, // hash of master password and plain text filename
    pub encrypted_data: String, // encrypted with the given nonce and from the derived key from the given salt
    pub file_salt: String, // the given salt
    pub file_nonce: String, // the given nonce
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MetaData {
    pub encrypted_filenames: Vec<String>, // those are encrypted with the given nonce and from the derived key from the given salt
    pub user_salt: String, // the given salt
    pub user_nonce: String, // the given nonce
    pub shared_secret: String, // this hash is the hash from the master password, no salt
}