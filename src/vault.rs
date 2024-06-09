use super::*;
use file_n_metadata::{UserEncryptedFile, UserEncryptedFolder, UserMetaData};
use sodiumoxide::base64::*;
use sodiumoxide::crypto::{box_, hash, pwhash, secretbox};
//use sodiumoxide::crypto::box_::keypair_from_seed;
//use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::{Seed};
use std::fs::File;
use std::io::{BufRead, BufReader, Error, ErrorKind, Write};

///this should control all access to db
#[derive(Debug)]
pub struct Vault {
    metadata_table_path: String,
    encrypted_file_table_path: String,
    encrypted_folder_table_path: String,
    metadata_vec: Vec<UserMetaData>,
    encrypted_files_vec: Vec<UserEncryptedFile>,
    encrypted_folders_vec: Vec<UserEncryptedFolder>,
}

impl Vault {
    fn new(
        path_metadata_vault: &str,
        path_enc_file_vault: &str,
        path_enc_folder_vault: &str,
    ) -> Vault {
        Vault {
            metadata_table_path: String::from(path_metadata_vault),
            encrypted_file_table_path: String::from(path_enc_file_vault),
            encrypted_folder_table_path: String::from(path_enc_folder_vault),
            metadata_vec: Vault::retrieve_all_metadata(path_metadata_vault),
            encrypted_files_vec: Vault::retrieve_all_encrypted_file(path_enc_file_vault),
            encrypted_folders_vec: Vault::retrieve_all_encrypted_folder(path_enc_folder_vault),
        }
    }

    pub fn default() -> Vault {
        Vault::new(
            constant::VAULT_METADATA_PATH,
            constant::VAULT_ENCRYPTED_FILE_PATH,
            constant::VAULT_ENCRYPTED_FOLDER_PATH,
        )
    }

    /*
        pub fn retrieve_all_metadata_shared_secret(&self) -> Vec<String> {
            let mut shared_secret_vec = Vec::new();
            for metadata in &self.metadata_vec {
                shared_secret_vec.push(metadata.shared_secret.clone());
            }
            return shared_secret_vec;
        }
    */
    pub fn retrieve_public_key_for(&self, user_name: &str) -> Result<String, &str> {
        match self
            .metadata_vec
            .iter()
            .find(|metadata| metadata.user_name == user_name)
        {
            Some(metadata) => Ok(metadata.user_public_key.clone()),
            None => Err("User not found."),
        }
    }

    pub fn retrieve_salt_for(&self, user_name: &str) -> Result<String, &str> {
        match self
            .metadata_vec
            .iter()
            .find(|metadata| metadata.user_name == user_name)
        {
            Some(metadata) => Ok(metadata.master_salt.clone()),
            None => Err("User not found."),
        }
    }

    /// as we never change the content, we should never have pbs
    pub fn retrieve_metadata_for(&self, username: &str) -> Result<&UserMetaData, &str> {
        match self
            .metadata_vec
            .iter()
            .find(|metadata| metadata.user_name == username)
        {
            Some(metadata) => Ok(metadata),
            None => Err("User not found."),
        }

    }

    /// as we never change the content, we should never have pbs
    pub fn retrieve_enc_file_by_b64_hash(
        &self,
        b64_hash: &str,
    ) -> Result<&UserEncryptedFile, Error> {
        match self
            .encrypted_files_vec
            .iter()
            .find(|&enc_file| enc_file.encrypted_file_name_hash == b64_hash)
        {
            Some(enc_file) => return Ok(enc_file),
            None => return Err(Error::new(ErrorKind::Other, format!("hash not found"))),
        }
    }

    /// as we never change the content, we should never have pbs
    pub fn retrieve_enc_folder_by_b64_hash(
        &self,
        b64_hash: &str,
    ) -> Result<&UserEncryptedFolder, Error> {
        match self
            .encrypted_folders_vec
            .iter()
            .find(|&enc_folder| enc_folder.encrypted_folder_name_hash == b64_hash)
        {
            Some(enc_folder) => return Ok(enc_folder),
            None => return Err(Error::new(ErrorKind::Other, format!("hash not found"))),
        }
    }

    /// static method
    fn retrieve_all_metadata(path: &str) -> Vec<UserMetaData> {
        let mut my_metadata_vec = Vec::new();

        match File::open(path) {
            Ok(input) => {
                let buffered = BufReader::new(input);
                for line in buffered.lines() {
                    my_metadata_vec.push(serde_json::from_str(line.unwrap().as_str()).unwrap());
                }
            }
            Err(_) => (), //do nothing if failed to open file
        }
        my_metadata_vec
    }

    /// static method
    fn retrieve_all_encrypted_file(path: &str) -> Vec<UserEncryptedFile> {
        let mut my_enc_file_vec = Vec::new();

        match File::open(path) {
            Ok(input) => {
                let buffered = BufReader::new(input);
                for line in buffered.lines() {
                    my_enc_file_vec.push(serde_json::from_str(line.unwrap().as_str()).unwrap());
                }
            }
            Err(_) => (), //do nothing if failed to open file
        }
        my_enc_file_vec
    }

    /// static method
    fn retrieve_all_encrypted_folder(path: &str) -> Vec<UserEncryptedFolder> {
        let mut my_enc_folder_vec = Vec::new();

        match File::open(path) {
            Ok(input) => {
                let buffered = BufReader::new(input);
                for line in buffered.lines() {
                    my_enc_folder_vec.push(serde_json::from_str(line.unwrap().as_str()).unwrap());
                }
            }
            Err(_) => (), //do nothing if failed to open file
        }
        my_enc_folder_vec
    }

    fn store_all_metadata(&self) -> () {
        let mut metadata_json = String::from("");
        let mut output = File::create(&self.metadata_table_path).unwrap(); // I'm okay with a panic here

        for metadata in &self.metadata_vec {
            // no need for copy as I just write the values
            metadata_json.push_str(&serde_json::to_string(&metadata).unwrap());
            metadata_json.push_str("\n");
        }

        write!(output, "{}", metadata_json); // I'm okay with a panic here
    }

    fn store_all_encrypted_file(&self) -> () {
        let mut encrypted_file_json = String::from("");
        let mut output = File::create(&self.encrypted_file_table_path).unwrap(); // I'm okay with a panic here

        for encrypted_file in &self.encrypted_files_vec {
            // no need for copy as I just write the values
            encrypted_file_json.push_str(&serde_json::to_string(&encrypted_file).unwrap());
            encrypted_file_json.push_str("\n");
        }

        write!(output, "{}", encrypted_file_json); // I'm okay with a panic here
    }

    fn store_all_encrypted_folder(&self) -> () {
        let mut encrypted_folder_json = String::from("");
        let mut output = File::create(&self.encrypted_folder_table_path).unwrap(); // I'm okay with a panic here

        for encrypted_folder in &self.encrypted_folders_vec {
            // no need for copy as I just write the values
            encrypted_folder_json.push_str(&serde_json::to_string(&encrypted_folder).unwrap());
            encrypted_folder_json.push_str("\n");
        }

        write!(output, "{}", encrypted_folder_json); // I'm okay with a panic here
    }

    fn store_all(&self) -> () {
        self.store_all_encrypted_file();
        self.store_all_encrypted_folder();
        self.store_all_metadata();
    }

    fn help_make_key(salt: &pwhash::Salt, passphrase: &str) -> [u8; 32] {
        let mut kx = secretbox::Key([0; secretbox::KEYBYTES]);
        let secretbox::Key(ref mut my_key) = kx;
        pwhash::derive_key(
            my_key,                // this is where the result is stored, à la C
            passphrase.as_bytes(), // we derive passphrase here
            salt,
            pwhash::OPSLIMIT_INTERACTIVE,
            pwhash::MEMLIMIT_INTERACTIVE,
        )
        .unwrap(); // unwrap just in case we get an error, in which case it should panic

        return *my_key;
    }

    fn help_make_hash(to_hash: &[u8]) -> hash::Digest {
        let mut hash_state = hash::State::new();
        hash_state.update(to_hash);
        return hash_state.finalize();
    }

    fn help_encrypt_data_sym(
        data_to_encrypt: &[u8],
        nonce: &secretbox::Nonce,
        xsalsa_key: &secretbox::Key,
    ) -> Vec<u8> {
        let to_bytes: &[u8] = data_to_encrypt;
        return secretbox::seal(to_bytes, nonce, xsalsa_key);
    }

    fn help_encrypt_data_asym(
        data_to_encrypt: &[u8],
        nonce: &box_::Nonce,
        receiver_pk: &box_::PublicKey,
        sender_sk: &box_::SecretKey,
    ) -> Vec<u8> {
        return box_::seal(
            data_to_encrypt,
            &nonce,
            receiver_pk,
            sender_sk,
        );
    }

    /// Ugly copy pasted code riddled with hard coded values
    ///
    /// Generates the default data
    ///
    /// Overwrites the files if not empty
    ///
    pub fn create_default_db() -> () {
        //init
        let mut my_vault = Vault::new(
            constant::VAULT_METADATA_PATH,
            constant::VAULT_ENCRYPTED_FILE_PATH,
            constant::VAULT_ENCRYPTED_FOLDER_PATH,
        );

        let mut my_metadata_vec: Vec<UserMetaData> = Vec::new();
        let mut my_enc_file_vec: Vec<UserEncryptedFile> = Vec::new();
        let mut my_enc_folder_vec: Vec<UserEncryptedFolder> = Vec::new();

        //=========================================================================================================
        //=========================================================================================================
        //=========================================================================================================

        //create the salt for the users
        let alban_salt = pwhash::gen_salt();
        let zalban_salt = pwhash::gen_salt();

        let alban_master_key = Self::help_make_key(&alban_salt, constant::TEST_STRONG_PASS_ALBAN);
        let zalban_master_key =
            Self::help_make_key(&zalban_salt, constant::TEST_STRONG_PASS_ZALBAN);

        // make key pair from alban master key
        let alban_public_key;
        let alban_secret_key;
        let alban_box_seed = box_::Seed::from_slice(&alban_master_key).unwrap();
        (alban_public_key, alban_secret_key) = box_::keypair_from_seed(&alban_box_seed);

        // make key pair from zalban master key
        let zalban_public_key;
        let zalban_secret_key;
        let zalban_box_seed = box_::Seed::from_slice(&zalban_master_key).unwrap();
        (zalban_public_key, zalban_secret_key) = box_::keypair_from_seed(&zalban_box_seed);

        // making xsalsa key from master key
        let alban_key_xsalsa = secretbox::Key::from_slice(&alban_master_key).unwrap();
        let zalban_key_xsalsa = secretbox::Key::from_slice(&zalban_master_key).unwrap();

        // making a nonce for the master key
        let alban_root_name_nonce = secretbox::gen_nonce();
        let zalban_root_name_nonce = secretbox::gen_nonce();
        let alban_root_key_nonce = secretbox::gen_nonce();
        let zalban_root_key_nonce = secretbox::gen_nonce();
        // we encrypt folder name of root only, WITH MASTER KEY
        // only Z and Y are owned by zalban
        let root_folder_name_encrypted_a = Self::help_encrypt_data_sym(
            constant::TEST_NAME_TO_ENCRYPT_A.as_bytes(),
            &alban_root_name_nonce,
            &alban_key_xsalsa,
        );
        let root_folder_name_encrypted_z = Self::help_encrypt_data_sym(
            constant::TEST_NAME_TO_ENCRYPT_Z.as_bytes(),
            &zalban_root_name_nonce,
            &zalban_key_xsalsa,
        );
        let encrypted_folder_name_hash_a = Self::help_make_hash(&root_folder_name_encrypted_a);
        let encrypted_folder_name_hash_z = Self::help_make_hash(&root_folder_name_encrypted_z);

        // we fill our struct for db
        let alban_metadata = UserMetaData {
            user_name: String::from(constant::TEST_USERNAME_ALBAN),
            encrypted_root_name_hash: encode(encrypted_folder_name_hash_a, Variant::UrlSafe),
            encrypted_root_name: encode(root_folder_name_encrypted_a, Variant::UrlSafe),

            encrypted_shared_folder_keys: Vec::new(),
            encrypted_shared_folder_names: Vec::new(),
            shared_folder_owner: Vec::new(),
            shared_folder_names_hash: Vec::new(),

            master_salt: encode(alban_salt, Variant::UrlSafe),
            root_name_nonce: encode(alban_root_name_nonce, Variant::UrlSafe),
            user_public_key: encode(alban_public_key, Variant::UrlSafe),
        };

        // we fill our struct for db
        let mut zalban_metadata = UserMetaData {
            user_name: String::from(constant::TEST_USERNAME_ZALBAN),
            encrypted_root_name_hash: encode(encrypted_folder_name_hash_z, Variant::UrlSafe),
            encrypted_root_name: encode(root_folder_name_encrypted_z, Variant::UrlSafe),

            encrypted_shared_folder_keys: Vec::new(),
            encrypted_shared_folder_names: Vec::new(),
            shared_folder_owner: Vec::new(),
            shared_folder_names_hash: Vec::new(),

            master_salt: encode(zalban_salt, Variant::UrlSafe),
            root_name_nonce: encode(zalban_root_name_nonce, Variant::UrlSafe),
            user_public_key: encode(zalban_public_key, Variant::UrlSafe),
        };

        //we push in vec
        //my_metadata_vec.push(alban_metadata);
        //my_metadata_vec.push(zalban_metadata);

        //=========================================================================================================
        //=========================================================================================================
        //=========================================================================================================

        // we will now encrypt the data of each file

        //we need a nonce for each file name
        let my_nonce_file_name_d = secretbox::gen_nonce();
        let my_nonce_file_name_e = secretbox::gen_nonce();
        let my_nonce_file_name_g = secretbox::gen_nonce();
        let my_nonce_file_name_h = secretbox::gen_nonce();
        let my_nonce_file_name_i = secretbox::gen_nonce();
        let my_nonce_file_name_y = secretbox::gen_nonce();

        //we need a nonce for each folder name except root
        //let my_nonce_folder_name_a = secretbox::gen_nonce();
        let my_nonce_folder_name_b = secretbox::gen_nonce();
        let my_nonce_folder_name_c = secretbox::gen_nonce();
        let my_nonce_folder_name_f = secretbox::gen_nonce();
        //let my_nonce_folder_name_z = secretbox::gen_nonce();

        //we need a nonce for each file
        let my_nonce_file_d: secretbox::Nonce = secretbox::gen_nonce();
        let my_nonce_file_e: secretbox::Nonce = secretbox::gen_nonce();
        let my_nonce_file_g: secretbox::Nonce = secretbox::gen_nonce();
        let my_nonce_file_h: secretbox::Nonce = secretbox::gen_nonce();
        let my_nonce_file_i: secretbox::Nonce = secretbox::gen_nonce();
        let my_nonce_file_y: secretbox::Nonce = secretbox::gen_nonce();

        // get a nonce for each key, except root
        let my_nonce_key_b = secretbox::gen_nonce();
        let my_nonce_key_c = secretbox::gen_nonce();
        let my_nonce_key_f = secretbox::gen_nonce();

        //we need a key for each folder
        let my_folder_key_a = secretbox::gen_key();
        let my_folder_key_b = secretbox::gen_key();
        let my_folder_key_c = secretbox::gen_key();
        let my_folder_key_f = secretbox::gen_key();
        let my_folder_key_z = secretbox::gen_key();

        //=========================================================================================================

        // we encrypt the file name, folder name and file data, AND FOLDER KEY
        //A
        let my_folder_name_encrypted_b = Self::help_encrypt_data_sym(
            constant::TEST_NAME_TO_ENCRYPT_B.as_bytes(),
            &my_nonce_folder_name_b,
            &my_folder_key_a,
        );
        let my_folder_name_encrypted_hash_b = Self::help_make_hash(&my_folder_name_encrypted_b);

        let my_folder_name_encrypted_c = Self::help_encrypt_data_sym(
            constant::TEST_NAME_TO_ENCRYPT_C.as_bytes(),
            &my_nonce_folder_name_c,
            &my_folder_key_a,
        );
        let my_folder_name_encrypted_hash_c = Self::help_make_hash(&my_folder_name_encrypted_c);

        let my_file_name_encrypted_d = Self::help_encrypt_data_sym(
            constant::TEST_NAME_TO_ENCRYPT_D.as_bytes(),
            &my_nonce_file_name_d,
            &my_folder_key_a,
        );
        let my_file_name_encrypted_hash_d = Self::help_make_hash(&my_file_name_encrypted_d);

        let my_file_encrypted_d = Self::help_encrypt_data_sym(
            constant::TEST_DATA_TO_ENCRYPT_D.as_bytes(),
            &my_nonce_file_d,
            &my_folder_key_a,
        );

        let my_folder_key_encrypted_a = Self::help_encrypt_data_sym(
            my_folder_key_a.as_ref(),
            &alban_root_key_nonce,
            &alban_key_xsalsa,
        );

        let mut encrypted_folder_names_hash_a_vec: Vec<String> = Vec::new();
        encrypted_folder_names_hash_a_vec
            .push(encode(my_folder_name_encrypted_hash_b, Variant::UrlSafe));
        encrypted_folder_names_hash_a_vec
            .push(encode(my_folder_name_encrypted_hash_c, Variant::UrlSafe));
        let mut encrypted_file_names_hash_a_vec: Vec<String> = Vec::new();
        encrypted_file_names_hash_a_vec
            .push(encode(my_file_name_encrypted_hash_d, Variant::UrlSafe));

        let mut encrypted_folder_names_a_vec: Vec<String> = Vec::new();
        encrypted_folder_names_a_vec.push(encode(my_folder_name_encrypted_b, Variant::UrlSafe));
        encrypted_folder_names_a_vec.push(encode(my_folder_name_encrypted_c, Variant::UrlSafe));
        let mut encrypted_file_names_a_vec: Vec<String> = Vec::new();
        encrypted_file_names_a_vec.push(encode(my_file_name_encrypted_d, Variant::UrlSafe));

        let mut file_name_nonces_a_vec: Vec<String> = Vec::new();
        file_name_nonces_a_vec.push(encode(my_nonce_file_name_d, Variant::UrlSafe));
        let mut folder_name_nonces_a_vec: Vec<String> = Vec::new();
        folder_name_nonces_a_vec.push(encode(my_nonce_folder_name_b, Variant::UrlSafe));
        folder_name_nonces_a_vec.push(encode(my_nonce_folder_name_c, Variant::UrlSafe));

        let my_folder_a = UserEncryptedFolder {
            encrypted_folder_name_hash: encode(encrypted_folder_name_hash_a, Variant::UrlSafe),
            owner: String::from(constant::TEST_USERNAME_ALBAN),
            is_currently_shared: false,

            encrypted_folder_key: encode(my_folder_key_encrypted_a, Variant::UrlSafe), // encrypted with the given nonce and from the derived key from the given salt
            encrypted_folder_names_hash: encrypted_folder_names_hash_a_vec, // encrypted with the given nonce and from the derived key from the given salt
            encrypted_file_names_hash: encrypted_file_names_hash_a_vec, // encrypted with the given nonce and from the derived key from the given salt
            encrypted_folder_names: encrypted_folder_names_a_vec, // encrypted with the given nonce and from the derived key from the given salt
            encrypted_file_names: encrypted_file_names_a_vec,
            file_name_nonces: file_name_nonces_a_vec, // the given file name nonce
            folder_name_nonces: folder_name_nonces_a_vec, // the given folder name nonce

            folder_key_nonce: encode(alban_root_key_nonce, Variant::UrlSafe), // this nonce used to encrypt this key
        };

        //B
        let my_file_name_encrypted_e = Self::help_encrypt_data_sym(
            constant::TEST_NAME_TO_ENCRYPT_E.as_bytes(),
            &my_nonce_file_name_e,
            &my_folder_key_b,
        );
        let my_file_name_encrypted_hash_e = Self::help_make_hash(&my_file_name_encrypted_e);

        let my_file_encrypted_e = Self::help_encrypt_data_sym(
            constant::TEST_DATA_TO_ENCRYPT_E.as_bytes(),
            &my_nonce_file_e,
            &my_folder_key_b,
        );

        let my_folder_key_encrypted_b = Self::help_encrypt_data_sym(
            my_folder_key_b.as_ref(),
            &my_nonce_key_b,
            &my_folder_key_a,
        );

        let encrypted_folder_names_hash_b_vec: Vec<String> = Vec::new();
        let mut encrypted_file_names_hash_b_vec: Vec<String> = Vec::new();
        encrypted_file_names_hash_b_vec
            .push(encode(my_file_name_encrypted_hash_e, Variant::UrlSafe));

        let encrypted_folder_names_b_vec: Vec<String> = Vec::new();
        let mut encrypted_file_names_b_vec: Vec<String> = Vec::new();
        encrypted_file_names_b_vec.push(encode(my_file_name_encrypted_e, Variant::UrlSafe));

        let mut file_name_nonces_b_vec: Vec<String> = Vec::new();
        file_name_nonces_b_vec.push(encode(my_nonce_file_name_e, Variant::UrlSafe));
        let folder_name_nonces_b_vec: Vec<String> = Vec::new();

        let my_folder_b = UserEncryptedFolder {
            encrypted_folder_name_hash: encode(my_folder_name_encrypted_hash_b, Variant::UrlSafe),
            owner: String::from(constant::TEST_USERNAME_ALBAN),
            is_currently_shared: false,

            encrypted_folder_key: encode(my_folder_key_encrypted_b, Variant::UrlSafe), // encrypted with the given nonce and from the derived key from the given salt
            encrypted_folder_names_hash: encrypted_folder_names_hash_b_vec, // encrypted with the given nonce and from the derived key from the given salt
            encrypted_file_names_hash: encrypted_file_names_hash_b_vec, // encrypted with the given nonce and from the derived key from the given salt
            encrypted_folder_names: encrypted_folder_names_b_vec, // encrypted with the given nonce and from the derived key from the given salt
            encrypted_file_names: encrypted_file_names_b_vec, // encrypted with the given nonce and from the derived key from the given salt

            file_name_nonces: file_name_nonces_b_vec, // the given file name nonce
            folder_name_nonces: folder_name_nonces_b_vec, // the given folder name nonce

            folder_key_nonce: encode(my_nonce_key_b, Variant::UrlSafe), // this nonce used to encrypt this key
        };

        //C
        let my_folder_name_encrypted_f = Self::help_encrypt_data_sym(
            constant::TEST_NAME_TO_ENCRYPT_F.as_bytes(),
            &my_nonce_folder_name_f,
            &my_folder_key_c,
        );
        let my_folder_name_encrypted_hash_f = Self::help_make_hash(&my_folder_name_encrypted_f);

        let my_file_name_encrypted_g = Self::help_encrypt_data_sym(
            constant::TEST_NAME_TO_ENCRYPT_G.as_bytes(),
            &my_nonce_file_name_g,
            &my_folder_key_c,
        );
        let my_file_name_encrypted_hash_g = Self::help_make_hash(&my_file_name_encrypted_g);

        let my_file_encrypted_g = Self::help_encrypt_data_sym(
            constant::TEST_DATA_TO_ENCRYPT_G.as_bytes(),
            &my_nonce_file_g,
            &my_folder_key_c,
        );

        let my_folder_key_encrypted_c = Self::help_encrypt_data_sym(
            my_folder_key_c.as_ref(),
            &my_nonce_key_c,
            &my_folder_key_a,
        );

        let mut encrypted_folder_names_hash_c_vec: Vec<String> = Vec::new();
        encrypted_folder_names_hash_c_vec
            .push(encode(my_folder_name_encrypted_hash_f, Variant::UrlSafe));
        let mut encrypted_file_names_hash_c_vec: Vec<String> = Vec::new();
        encrypted_file_names_hash_c_vec
            .push(encode(my_file_name_encrypted_hash_g, Variant::UrlSafe));

        let mut encrypted_folder_names_c_vec: Vec<String> = Vec::new();
        encrypted_folder_names_c_vec.push(encode(my_folder_name_encrypted_f, Variant::UrlSafe));
        let mut encrypted_file_names_c_vec: Vec<String> = Vec::new();
        encrypted_file_names_c_vec.push(encode(my_file_name_encrypted_g, Variant::UrlSafe));

        let mut file_name_nonces_c_vec: Vec<String> = Vec::new();
        file_name_nonces_c_vec.push(encode(my_nonce_file_name_g, Variant::UrlSafe));
        let mut folder_name_nonces_c_vec: Vec<String> = Vec::new();
        folder_name_nonces_c_vec.push(encode(my_nonce_folder_name_f, Variant::UrlSafe));

        let my_folder_c = UserEncryptedFolder {
            encrypted_folder_name_hash: encode(my_folder_name_encrypted_hash_c, Variant::UrlSafe),
            owner: String::from(constant::TEST_USERNAME_ALBAN),
            is_currently_shared: false,

            encrypted_folder_key: encode(my_folder_key_encrypted_c, Variant::UrlSafe), // encrypted with the given nonce and from the derived key from the given salt
            encrypted_folder_names_hash: encrypted_folder_names_hash_c_vec, // encrypted with the given nonce and from the derived key from the given salt
            encrypted_file_names_hash: encrypted_file_names_hash_c_vec, // encrypted with the given nonce and from the derived key from the given salt
            encrypted_folder_names: encrypted_folder_names_c_vec, // encrypted with the given nonce and from the derived key from the given salt
            encrypted_file_names: encrypted_file_names_c_vec, // encrypted with the given nonce and from the derived key from the given salt

            file_name_nonces: file_name_nonces_c_vec, // the given file name nonce
            folder_name_nonces: folder_name_nonces_c_vec, // the given folder name nonce

            folder_key_nonce: encode(my_nonce_key_c, Variant::UrlSafe), // this nonce used to encrypt this key
        };

        //F
        let my_file_name_encrypted_h = Self::help_encrypt_data_sym(
            constant::TEST_NAME_TO_ENCRYPT_H.as_bytes(),
            &my_nonce_file_name_h,
            &my_folder_key_f,
        );
        let my_file_name_encrypted_hash_h = Self::help_make_hash(&my_file_name_encrypted_h);

        let my_file_encrypted_h = Self::help_encrypt_data_sym(
            constant::TEST_DATA_TO_ENCRYPT_H.as_bytes(),
            &my_nonce_file_h,
            &my_folder_key_f,
        );

        let my_file_name_encrypted_i = Self::help_encrypt_data_sym(
            constant::TEST_NAME_TO_ENCRYPT_I.as_bytes(),
            &my_nonce_file_name_i,
            &my_folder_key_f,
        );
        let my_file_name_encrypted_hash_i = Self::help_make_hash(&my_file_name_encrypted_i);

        let my_file_encrypted_i = Self::help_encrypt_data_sym(
            constant::TEST_DATA_TO_ENCRYPT_I.as_bytes(),
            &my_nonce_file_i,
            &my_folder_key_f,
        );

        let my_folder_key_encrypted_f = Self::help_encrypt_data_sym(
            my_folder_key_f.as_ref(),
            &my_nonce_key_f,
            &my_folder_key_c,
        );

        let encrypted_folder_names_hash_f_vec: Vec<String> = Vec::new();
        let mut encrypted_file_names_hash_f_vec: Vec<String> = Vec::new();
        encrypted_file_names_hash_f_vec
            .push(encode(my_file_name_encrypted_hash_h, Variant::UrlSafe));
        encrypted_file_names_hash_f_vec
            .push(encode(my_file_name_encrypted_hash_i, Variant::UrlSafe));

        let encrypted_folder_names_f_vec: Vec<String> = Vec::new();
        let mut encrypted_file_names_f_vec: Vec<String> = Vec::new();
        encrypted_file_names_f_vec.push(encode(my_file_name_encrypted_h, Variant::UrlSafe));
        encrypted_file_names_f_vec.push(encode(my_file_name_encrypted_i, Variant::UrlSafe));

        let mut file_name_nonces_f_vec: Vec<String> = Vec::new();
        file_name_nonces_f_vec.push(encode(my_nonce_file_name_h, Variant::UrlSafe));
        file_name_nonces_f_vec.push(encode(my_nonce_file_name_i, Variant::UrlSafe));
        let folder_name_nonces_f_vec: Vec<String> = Vec::new();

        let my_folder_f = UserEncryptedFolder {
            encrypted_folder_name_hash: encode(my_folder_name_encrypted_hash_f, Variant::UrlSafe),
            owner: String::from(constant::TEST_USERNAME_ALBAN),
            is_currently_shared: false,

            encrypted_folder_key: encode(my_folder_key_encrypted_f, Variant::UrlSafe), // encrypted with the given nonce and from the derived key from the given salt
            encrypted_folder_names_hash: encrypted_folder_names_hash_f_vec, // encrypted with the given nonce and from the derived key from the given salt
            encrypted_file_names_hash: encrypted_file_names_hash_f_vec, // encrypted with the given nonce and from the derived key from the given salt
            encrypted_folder_names: encrypted_folder_names_f_vec, // encrypted with the given nonce and from the derived key from the given salt
            encrypted_file_names: encrypted_file_names_f_vec, // encrypted with the given nonce and from the derived key from the given salt

            file_name_nonces: file_name_nonces_f_vec, // the given file name nonce
            folder_name_nonces: folder_name_nonces_f_vec, // the given folder name nonce

            folder_key_nonce: encode(my_nonce_key_f, Variant::UrlSafe), // this nonce used to encrypt this key
        };

        //Z
        let my_file_name_encrypted_y = Self::help_encrypt_data_sym(
            constant::TEST_NAME_TO_ENCRYPT_Y.as_bytes(),
            &my_nonce_file_name_y,
            &my_folder_key_z,
        );
        let my_file_name_encrypted_hash_y = Self::help_make_hash(&my_file_name_encrypted_y);

        let my_file_encrypted_y = Self::help_encrypt_data_sym(
            constant::TEST_DATA_TO_ENCRYPT_Y.as_bytes(),
            &my_nonce_file_y,
            &my_folder_key_z,
        );

        let my_folder_key_encrypted_z = Self::help_encrypt_data_sym(
            my_folder_key_z.as_ref(),
            &zalban_root_key_nonce,
            &zalban_key_xsalsa,
        );

        let encrypted_folder_names_hash_z_vec: Vec<String> = Vec::new();
        let mut encrypted_file_names_hash_z_vec: Vec<String> = Vec::new();
        encrypted_file_names_hash_z_vec
            .push(encode(my_file_name_encrypted_hash_y, Variant::UrlSafe));

        let encrypted_folder_names_z_vec: Vec<String> = Vec::new();
        let mut encrypted_file_names_z_vec: Vec<String> = Vec::new();
        encrypted_file_names_z_vec.push(encode(my_file_name_encrypted_y, Variant::UrlSafe));

        let mut file_name_nonces_z_vec: Vec<String> = Vec::new();
        file_name_nonces_z_vec.push(encode(my_nonce_file_name_y, Variant::UrlSafe));
        let folder_name_nonces_z_vec: Vec<String> = Vec::new();

        let my_folder_z = UserEncryptedFolder {
            encrypted_folder_name_hash: encode(encrypted_folder_name_hash_z, Variant::UrlSafe),
            owner: String::from(constant::TEST_USERNAME_ZALBAN),
            is_currently_shared: false,

            encrypted_folder_key: encode(my_folder_key_encrypted_z, Variant::UrlSafe),
            encrypted_folder_names_hash: encrypted_folder_names_hash_z_vec,
            encrypted_file_names_hash: encrypted_file_names_hash_z_vec,
            encrypted_folder_names: encrypted_folder_names_z_vec,
            encrypted_file_names: encrypted_file_names_z_vec,

            file_name_nonces: file_name_nonces_z_vec,
            folder_name_nonces: folder_name_nonces_z_vec,

            folder_key_nonce: encode(zalban_root_key_nonce, Variant::UrlSafe),
        };

        //=========================================================================================================

        let my_file_d = UserEncryptedFile {
            encrypted_file_name_hash: encode(my_file_name_encrypted_hash_d, Variant::UrlSafe), // to identify the file, cypher text hash
            owner_hash: String::from(constant::TEST_USERNAME_ALBAN), // username hash, is not private, to identify the alban:/home/alban/my_text.txt

            encrypted_data: encode(my_file_encrypted_d, Variant::UrlSafe),

            file_nonce: encode(my_nonce_file_d, Variant::UrlSafe),
        };

        let my_file_e = UserEncryptedFile {
            encrypted_file_name_hash: encode(my_file_name_encrypted_hash_e, Variant::UrlSafe), // to identify the file, cypher text hash
            owner_hash: String::from(constant::TEST_USERNAME_ALBAN), // username hash, is not private, to identify the alban:/home/alban/my_text.txt

            encrypted_data: encode(my_file_encrypted_e, Variant::UrlSafe),

            file_nonce: encode(my_nonce_file_e, Variant::UrlSafe),
        };

        let my_file_g = UserEncryptedFile {
            encrypted_file_name_hash: encode(my_file_name_encrypted_hash_g, Variant::UrlSafe), // to identify the file, cypher text hash
            owner_hash: String::from(constant::TEST_USERNAME_ALBAN), // username hash, is not private, to identify the alban:/home/alban/my_text.txt

            encrypted_data: encode(my_file_encrypted_g, Variant::UrlSafe),

            file_nonce: encode(my_nonce_file_g, Variant::UrlSafe),
        };

        let my_file_h = UserEncryptedFile {
            encrypted_file_name_hash: encode(my_file_name_encrypted_hash_h, Variant::UrlSafe), // to identify the file, cypher text hash
            owner_hash: String::from(constant::TEST_USERNAME_ALBAN), // username hash, is not private, to identify the alban:/home/alban/my_text.txt

            encrypted_data: encode(my_file_encrypted_h, Variant::UrlSafe),

            file_nonce: encode(my_nonce_file_h, Variant::UrlSafe),
        };

        let my_file_i = UserEncryptedFile {
            encrypted_file_name_hash: encode(my_file_name_encrypted_hash_i, Variant::UrlSafe), // to identify the file, cypher text hash
            owner_hash: String::from(constant::TEST_USERNAME_ALBAN), // username hash, is not private, to identify the alban:/home/alban/my_text.txt

            encrypted_data: encode(my_file_encrypted_i, Variant::UrlSafe),

            file_nonce: encode(my_nonce_file_i, Variant::UrlSafe),
        };

        let my_file_y = UserEncryptedFile {
            encrypted_file_name_hash: encode(my_file_name_encrypted_hash_y, Variant::UrlSafe), // to identify the file, cypher text hash
            owner_hash: String::from(constant::TEST_USERNAME_ZALBAN), // username hash, is not private, to identify the alban:/home/alban/my_text.txt

            encrypted_data: encode(my_file_encrypted_y, Variant::UrlSafe),

            file_nonce: encode(my_nonce_file_y, Variant::UrlSafe),
        };

        // we push our structs in vault and write the db
        my_enc_file_vec.push(my_file_d);
        my_enc_file_vec.push(my_file_e);
        my_enc_file_vec.push(my_file_g);
        my_enc_file_vec.push(my_file_h);
        my_enc_file_vec.push(my_file_i);
        my_enc_file_vec.push(my_file_y);

        my_enc_folder_vec.push(my_folder_a);
        my_enc_folder_vec.push(my_folder_b);
        my_enc_folder_vec.push(my_folder_c);
        my_enc_folder_vec.push(my_folder_f);
        my_enc_folder_vec.push(my_folder_z);

        // share c to zalban
        let c_shared_folder_name_nonce = box_::gen_nonce();
        let c_shared_folder_key_nonce = box_::gen_nonce();
        let asym_encrypted_folder_name_c = Vault::help_encrypt_data_asym(constant::TEST_NAME_TO_ENCRYPT_C.as_bytes(),&c_shared_folder_name_nonce,&zalban_public_key,&alban_secret_key);
        let asym_encrypted_folder_key_c = Vault::help_encrypt_data_asym(my_folder_key_c.as_ref(),&c_shared_folder_key_nonce,&zalban_public_key,&alban_secret_key);
        
        //push in zalban metadata
        zalban_metadata.shared_folder_owner.push(constant::TEST_USERNAME_ALBAN.to_string());
        zalban_metadata.encrypted_shared_folder_names.push((encode(asym_encrypted_folder_name_c, Variant::UrlSafe),encode(c_shared_folder_name_nonce, Variant::UrlSafe)));
        zalban_metadata.encrypted_shared_folder_keys.push((encode(asym_encrypted_folder_key_c, Variant::UrlSafe),encode(c_shared_folder_key_nonce, Variant::UrlSafe)));
        zalban_metadata.shared_folder_names_hash.push(encode(my_folder_name_encrypted_hash_c, Variant::UrlSafe));

        my_metadata_vec.push(alban_metadata);
        my_metadata_vec.push(zalban_metadata);

        my_vault.metadata_vec = my_metadata_vec;
        my_vault.encrypted_files_vec = my_enc_file_vec;
        my_vault.encrypted_folders_vec = my_enc_folder_vec;
        my_vault.store_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_filenames() {
        let test_metadata_vec = Vault::retrieve_all_metadata(constant::VAULT_METADATA_PATH);

        // we have to find master key

        let my_user_salt_slice =
            decode(&test_metadata_vec[0].master_salt, Variant::UrlSafe).unwrap();
        let my_user_salt = pwhash::Salt::from_slice(&my_user_salt_slice).unwrap();

        let mut mk = secretbox::Key([0; secretbox::KEYBYTES]);
        let secretbox::Key(ref mut my_master_pass) = mk;
        pwhash::derive_key(
            my_master_pass,
            constant::TEST_STRONG_PASS_ALBAN.as_bytes(), // we derive master pass here
            &my_user_salt,
            pwhash::OPSLIMIT_INTERACTIVE,
            pwhash::MEMLIMIT_INTERACTIVE,
        )
        .unwrap();

        //we have to find xsalsa key
        let a_master_key = secretbox::Key::from_slice(my_master_pass).unwrap();

        //we have to retriev the nonce
        let my_nonce_slice =
            decode(&test_metadata_vec[0].root_name_nonce, Variant::UrlSafe).unwrap();
        let my_nonce = secretbox::Nonce::from_slice(&my_nonce_slice).unwrap();

        // we decrypt to check if it works
        //let mut my_deciphered_test_name_vec: Vec<String> = Vec::new();

        let ct_root_name_hash = test_metadata_vec[0].encrypted_root_name_hash.clone();
        let ct_root_name = test_metadata_vec[0].encrypted_root_name.clone();

        let test_enc_folder_vec =
            Vault::retrieve_all_encrypted_folder(constant::VAULT_ENCRYPTED_FOLDER_PATH);

        let root_folder: &UserEncryptedFolder = test_enc_folder_vec
            .iter()
            .find(|&enc_folder| enc_folder.encrypted_folder_name_hash == ct_root_name_hash)
            .unwrap();

        let decoded_enc_root_name = decode(ct_root_name, Variant::UrlSafe).unwrap();
        let my_deciphered_root_name = String::from_utf8(
            secretbox::open(&decoded_enc_root_name, &my_nonce, &a_master_key).unwrap(),
        )
        .unwrap();
        assert_eq!(my_deciphered_root_name, constant::TEST_NAME_TO_ENCRYPT_A);

        assert_eq!(
            root_folder.encrypted_folder_names.len(),
            root_folder.encrypted_folder_names_hash.len(),
            "folder names and folder hashs are not the same size"
        );

        assert_eq!(
            root_folder.folder_name_nonces.len(),
            root_folder.encrypted_folder_names_hash.len(),
            "folder nonces and folder hashes are not the same size"
        );

        assert_eq!(
            root_folder.encrypted_file_names_hash.len(),
            root_folder.encrypted_file_names.len(),
            "filenames and file hashes are not the same size"
        );

        assert_eq!(
            root_folder.file_name_nonces.len(),
            root_folder.encrypted_file_names_hash.len(),
            "folder hashes and folder nonces are not the same size"
        );
        let a_key_decoded_nonce = decode(&root_folder.folder_key_nonce, Variant::UrlSafe).unwrap();
        let a_key_nonce = secretbox::Nonce::from_slice(&a_key_decoded_nonce).unwrap();

        let a_key_decoded = decode(&root_folder.encrypted_folder_key, Variant::UrlSafe).unwrap();
        let a_key_deciphered =
            secretbox::open(&a_key_decoded, &a_key_nonce, &a_master_key).unwrap();
        let a_key = secretbox::Key::from_slice(&a_key_deciphered).unwrap();

        let mut my_deciphered_test_filename_vec: Vec<String> = Vec::new();
        for i in 0..root_folder.file_name_nonces.len() {
            let decoded_enc_name = decode(
                root_folder.encrypted_file_names[i].clone(),
                Variant::UrlSafe,
            )
            .unwrap();
            let my_nonce_slice =
                decode(root_folder.file_name_nonces[i].clone(), Variant::UrlSafe).unwrap();
            let nonce = secretbox::Nonce::from_slice(&my_nonce_slice).unwrap();

            //wrong key, need real root key

            let my_deciphered_test_filename =
                secretbox::open(&decoded_enc_name, &nonce, &a_key).unwrap();
            my_deciphered_test_filename_vec
                .push(String::from_utf8(my_deciphered_test_filename).unwrap());
        }
        assert_eq!(my_deciphered_test_filename_vec.len(), 1);

        assert_eq!(
            my_deciphered_test_filename_vec[0],
            constant::TEST_NAME_TO_ENCRYPT_D
        );
    }
    /*
    #[test]
    fn verify_files() {
        let test_enc_file_vec =
            Vault::retrieve_all_encrypted_file(constant::VAULT_ENCRYPTED_FILE_PATH);

        // decrypting filenames is pointless :/

        // we have to find all files key

        let mut decrypted_data_vec: Vec<String> = Vec::new();
        let mut pt_hash_vec = Vec::new();

        for file in test_enc_file_vec {
            let my_file_hash_slice = decode(file.file_salt, Variant::UrlSafe).unwrap();
            let my_file_hash = pwhash::Salt::from_slice(&my_file_hash_slice).unwrap();

            let mut k = secretbox::Key([0; secretbox::KEYBYTES]);
            let secretbox::Key(ref mut my_key) = k;
            pwhash::derive_key(
                my_key,
                constant::TEST_STRONG_PASS.as_bytes(), // we derive master pass here
                &my_file_hash,
                pwhash::OPSLIMIT_INTERACTIVE,
                pwhash::MEMLIMIT_INTERACTIVE,
            )
            .unwrap();

            //we have to find xsalsa key
            let my_key_xsalsa = secretbox::Key::from_slice(my_key).unwrap();

            //we have to retriev the nonce
            let my_nonce_slice = decode(&file.file_nonce, Variant::UrlSafe).unwrap();
            let my_nonce = secretbox::Nonce::from_slice(&my_nonce_slice).unwrap();

            let decoded_enc_data = decode(file.encrypted_data, Variant::UrlSafe).unwrap();
            let my_deciphered_data =
                secretbox::open(&decoded_enc_data, &my_nonce, &my_key_xsalsa).unwrap();
            decrypted_data_vec.push(String::from_utf8(my_deciphered_data).unwrap());

            let pt_hash_slice = decode(file.pt_filename_hash, Variant::UrlSafe).unwrap();
            pt_hash_vec.push(hash::Digest::from_slice(&pt_hash_slice).unwrap());
        }

        // we get the pt hash
        let mut hash_state1 = hash::State::new();
        hash_state1.update(constant::TEST_STRONG_PASS.as_bytes());
        hash_state1.update(constant::TEST_NAME_TO_ENCRYPT.as_bytes());
        let digest1 = hash_state1.finalize();

        let mut hash_state2 = hash::State::new();
        hash_state2.update(constant::TEST_STRONG_PASS.as_bytes());
        hash_state2.update(constant::TEST_NAME_TO_ENCRYPT_2.as_bytes());
        let digest2 = hash_state2.finalize();

        let mut hash_state3 = hash::State::new();
        hash_state3.update(constant::TEST_STRONG_PASS.as_bytes());
        hash_state3.update(constant::TEST_NAME_TO_ENCRYPT_3.as_bytes());
        let digest3 = hash_state3.finalize();

        let mut hash_state4 = hash::State::new();
        hash_state4.update(constant::TEST_STRONG_PASS.as_bytes());
        hash_state4.update(constant::TEST_NAME_TO_ENCRYPT_4.as_bytes());
        let digest4 = hash_state4.finalize();

        assert_eq!(pt_hash_vec[0], digest1);
        assert_eq!(pt_hash_vec[1], digest2);
        assert_eq!(pt_hash_vec[2], digest3);
        assert_eq!(pt_hash_vec[3], digest4);

        assert_eq!(decrypted_data_vec[0], constant::TEST_DATA_TO_ENCRYPT);
        assert_eq!(decrypted_data_vec[1], constant::TEST_DATA_TO_ENCRYPT_2);
        assert_eq!(decrypted_data_vec[2], constant::TEST_DATA_TO_ENCRYPT_3);
        assert_eq!(decrypted_data_vec[3], constant::TEST_DATA_TO_ENCRYPT_4);
    }

    #[test]
    fn vault_md_retrieval() {
        let test_vault = Vault::default();

        let test_metad = &test_vault.metadata_vec[0];

        // we have to find master key

        let my_user_salt_slice = decode(&test_metad.user_salt, Variant::UrlSafe).unwrap();
        let my_user_salt = pwhash::Salt::from_slice(&my_user_salt_slice).unwrap();

        let mut mk = secretbox::Key([0; secretbox::KEYBYTES]);
        let secretbox::Key(ref mut my_master_key) = mk;
        pwhash::derive_key(
            my_master_key,
            constant::TEST_STRONG_PASS.as_bytes(), // we derive master pass here
            &my_user_salt,
            pwhash::OPSLIMIT_INTERACTIVE,
            pwhash::MEMLIMIT_INTERACTIVE,
        )
        .unwrap();

        //we have to find xsalsa key
        let my_key_xsalsa = secretbox::Key::from_slice(my_master_key).unwrap();

        //we have to retriev the nonce
        let my_nonce_slice = decode(&test_metad.user_nonce, Variant::UrlSafe).unwrap();
        let my_nonce = secretbox::Nonce::from_slice(&my_nonce_slice).unwrap();

        // we decrypt to check if it works
        let mut my_deciphered_test_name_vec: Vec<String> = Vec::new();
        for enc_name in &test_metad.encrypted_filenames {
            let decoded_enc_name = decode(enc_name, Variant::UrlSafe).unwrap();
            let my_deciphered_test_name =
                secretbox::open(&decoded_enc_name, &my_nonce, &my_key_xsalsa).unwrap();
            my_deciphered_test_name_vec.push(String::from_utf8(my_deciphered_test_name).unwrap());
        }

        assert_eq!(
            my_deciphered_test_name_vec[0],
            constant::TEST_NAME_TO_ENCRYPT
        );
        assert_eq!(
            my_deciphered_test_name_vec[1],
            constant::TEST_NAME_TO_ENCRYPT_2
        );
        assert_eq!(
            my_deciphered_test_name_vec[2],
            constant::TEST_NAME_TO_ENCRYPT_3
        );
        assert_eq!(
            my_deciphered_test_name_vec[3],
            constant::TEST_NAME_TO_ENCRYPT_4
        );
    }*/
}
