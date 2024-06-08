use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct UserEncryptedFile {
    pub encrypted_file_name_hash: String, // to identify the file, cypher text hash
    pub owner_hash: String, // username hash, is not private, to identify the alban:/home/alban/my_text.txt

    //pub encrypted_file_name: String, // encrypted with the given nonce and from the derived key from the given salt
    pub encrypted_data: String, // encrypted with the given nonce and from the derived key from the given salt

    //pub file_salt: String,  // the given salt
    pub file_nonce: String, // the given file nonce
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserEncryptedFolder {
    pub encrypted_folder_name_hash: String, // identfiy the folder, cypher text hash
    pub owner: String, // username, is not private, to identify the folder alban:/home/alban
    pub is_currently_shared: bool, // tells if this folder is currently shared


    pub encrypted_folder_key: String, // encrypted with the given nonce and from the derived key from the given salt
    pub encrypted_folder_names_hash: Vec<String>, // encrypted with the given nonce and from the derived key from the given salt
    pub encrypted_folder_names: Vec<String>, // encrypted with the given nonce and from the derived key from the given salt
    pub encrypted_file_names_hash: Vec<String>, // encrypted with the given nonce and from the derived key from the given salt
    pub encrypted_file_names: Vec<String>, // encrypted with the given nonce and from the derived key from the given salt

    pub file_name_nonces: Vec<String>, // the given file name nonce
    pub folder_name_nonces: Vec<String>, // the given folder name nonce

    //these two can be used to retrieve the key with the previous key
    //pub folder_key_salt: String,       // the given salt to derive this folder's key
    pub folder_key_nonce: String, // this nonce used to encrypt this key
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserMetaData {
    pub user_name: String,                // needed to share folder with people
    pub encrypted_root_name_hash: String, // those are encrypted with the given nonce and from the derived key from the given salt
    pub encrypted_root_name: String, // those are encrypted with the given nonce and from the derived key from the given salt

    pub encrypted_shared_folder_owner: Vec<String>, // asym, to get salt and nonce, also part of name in this context
    pub encrypted_shared_folder_names: Vec<String>, // asym, to get the ENCRYPTED file name, needs to be decrypted with the shared key
    pub encrypted_shared_folder_keys: Vec<String>,  // asym, the sharer folder key
    pub shared_folder_names_hash: Vec<String>,      // to identify folder

    pub master_salt: String,     // used to derive master key
    pub root_name_nonce: String, // used to encrypt root name with master key
    //pub root_key_nonce: String,      // is in root instead
    pub user_public_key: String, // user public key, so that we can share with them
}
