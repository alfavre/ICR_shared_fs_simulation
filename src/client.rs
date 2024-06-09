use std::sync::mpsc::Receiver;

use super::*;
use read_input::prelude::*;
use server::Server;
use sodiumoxide::base64::*;
use sodiumoxide::crypto;
use sodiumoxide::crypto::*;

pub struct Client {
    master_password: String,
    username: String,
    master_key: Option<[u8; 32]>,
    pk: Option<box_::PublicKey>,
    sk: Option<box_::SecretKey>,
    current_folder: String, // necessary ?
}

impl Client {
    fn new(username: String, master_password: String) -> Client {
        Client {
            master_password: master_password,
            username: username,
            master_key: None,
            pk: None,
            sk: None,
            current_folder: "\\".to_string(),
        }
    }

    fn answer_challenge(
        &self,
        encrypted_response: Vec<u8>,
        nonce: &box_::Nonce,
        server_pk: &box_::PublicKey,
    ) -> Result<String, &str> {
        let dec_challenge = box_::open(
            &encrypted_response,
            &nonce,
            server_pk,
            &self.sk.clone().unwrap(),
        );

        match dec_challenge {
            Ok(utf8) => return Ok(String::from_utf8(utf8).expect("Challenge was not utf 8")), // in theory here we could get a non utf8, but it is cool
            Err(_) => Err("Wrong password or user"),
        }
    }

    fn load_master_key(&mut self, b64_salt: &str) -> () {
        let my_salt_slice = decode(b64_salt, Variant::UrlSafe).unwrap();
        let my_salt = pwhash::Salt::from_slice(&my_salt_slice).unwrap();

        let mut kx = secretbox::Key([0; secretbox::KEYBYTES]);
        let secretbox::Key(ref mut my_key) = kx;
        pwhash::derive_key(
            my_key,                          // this is where the result is stored, à la C
            self.master_password.as_bytes(), // we derive passphrase here
            &my_salt,
            pwhash::OPSLIMIT_INTERACTIVE,
            pwhash::MEMLIMIT_INTERACTIVE,
        )
        .unwrap();
        // unwrap just in case we get an error, in which case it should panic

        self.master_key = Some(*my_key);
    }

    fn load_key_pair(&mut self) -> () {
        // make key pair from master password
        let public_key;
        let secret_key;
        let box_seed =
            box_::Seed::from_slice(&self.master_key.expect("master key not yet loaded")).unwrap();
        (public_key, secret_key) = box_::keypair_from_seed(&box_seed);
        self.sk = Some(secret_key);
        self.pk = Some(public_key);
    }

    fn decipher_asym_text(
        &self,
        b64_encrypted_text: &str,
        sender_pk: &box_::PublicKey,
        b64_nonce: &str,
    ) -> String {
        String::from_utf8(self.decipher_asym_core(b64_encrypted_text, sender_pk, b64_nonce))
            .unwrap()
    }

    fn decipher_asym_key(
        &self,
        b64_encrypted_text: &str,
        sender_pk: &box_::PublicKey,
        b64_nonce: &str,
    ) -> secretbox::Key {
        secretbox::Key::from_slice(&self.decipher_asym_core(
            b64_encrypted_text,
            sender_pk,
            b64_nonce,
        ))
        .unwrap()
    }

    fn decipher_asym_core(
        &self,
        b64_encrypted_text: &str,
        sender_pk: &box_::PublicKey,
        b64_nonce: &str,
    ) -> Vec<u8> {
        let my_nonce_slice = decode(&b64_nonce, Variant::UrlSafe).unwrap();
        let my_nonce = box_::Nonce::from_slice(&my_nonce_slice).unwrap();

        let decoded_stuff = decode(b64_encrypted_text, Variant::UrlSafe).unwrap();

        let deciphered_stuff = box_::open(
            &decoded_stuff,
            &my_nonce,
            &sender_pk,
            &self.sk.clone().unwrap(), // we will never receive for someone else than us
        )
        .expect("fug");

        return deciphered_stuff;
    }

    fn decipher_sym_text(
        &self,
        b64_encrypted_text: &str,
        b64_nonce: &str,
        sym_key: &secretbox::Key,
    ) -> String {
        String::from_utf8(self.decipher_sym_core(b64_encrypted_text, b64_nonce, sym_key)).unwrap()
    }

    fn decipher_sym_key(
        &self,
        b64_encrypted_text: &str,
        b64_nonce: &str,
        sym_key: &secretbox::Key,
    ) -> secretbox::Key {
        println!("salut");
        secretbox::Key::from_slice(&self.decipher_sym_core(b64_encrypted_text, b64_nonce, sym_key))
            .unwrap()
    }

    pub fn to_sym_key(slice_key: &[u8; 32]) -> secretbox::Key {
        return secretbox::Key::from_slice(slice_key).unwrap();
    }

    fn decipher_sym_core(
        &self,
        b64_encrypted_text: &str,
        b64_nonce: &str,
        sym_key: &secretbox::Key,
    ) -> Vec<u8> {
        let my_nonce_slice = decode(&b64_nonce, Variant::UrlSafe).unwrap();
        let my_nonce = secretbox::Nonce::from_slice(&my_nonce_slice).unwrap();

        let decoded_stuff = decode(b64_encrypted_text, Variant::UrlSafe).unwrap();
        let my_deciphered_stuff = secretbox::open(&decoded_stuff, &my_nonce, sym_key).unwrap();

        //String::from_utf8(my_deciphered_stuff).unwrap()
        return my_deciphered_stuff;
    }
    /*
    fn decrypt_stuff(&self, b64_encrypted_text: &str, b64_salt: &str, b64_nonce: &str) -> String {
        let my_salt_slice = decode(b64_salt, Variant::UrlSafe).unwrap();
        let my_salt = pwhash::Salt::from_slice(&my_salt_slice).unwrap();

        let my_nonce_slice = decode(&b64_nonce, Variant::UrlSafe).unwrap();
        let my_nonce = secretbox::Nonce::from_slice(&my_nonce_slice).unwrap();

        let mut k: secretbox::Key = secretbox::Key([0; secretbox::KEYBYTES]);
        let secretbox::Key(ref mut my_key) = k;
        pwhash::derive_key(
            my_key,
            self.master_password.as_bytes(), // we derive master pass here
            &my_salt,
            pwhash::OPSLIMIT_INTERACTIVE,
            pwhash::MEMLIMIT_INTERACTIVE,
        )
        .unwrap();

        let my_key_xsalsa = secretbox::Key::from_slice(my_key).unwrap();

        let decoded_stuff = decode(b64_encrypted_text, Variant::UrlSafe).unwrap();
        let my_deciphered_stuff =
            secretbox::open(&decoded_stuff, &my_nonce, &my_key_xsalsa).unwrap();

        String::from_utf8(my_deciphered_stuff).unwrap()
    }*/

    /*
    fn get_pt_hash_in_b64(&self, pt_filename: &str) -> String {
        let mut hash_state = hash::State::new();
        hash_state.update(self.master_password.as_bytes());
        hash_state.update(pt_filename.as_bytes());
        let digest = hash_state.finalize();
        encode(digest, Variant::UrlSafe)
    }*/

    fn handle_exchange(&self, server: &Server) {
        println!("We will fetch the list of all your files and folders, please wait a moment.");
        let my_mt = server.ask_for_metadata(self.username.as_str()); // this will never leave this scope in theory
        let folder_hash_and_key: (String, secretbox::Key);

        let my_decrypted_root_name = self.decipher_sym_text(
            my_mt.encrypted_root_name.as_str(),
            my_mt.root_name_nonce.as_str(),
            &Client::to_sym_key(&self.master_key.unwrap()),
        );

        println!(
            "Your root folder is: {}:{}.",
            self.username, my_decrypted_root_name
        );

        println!(
            "You have access to {} shared folder(s).",
            my_mt.encrypted_shared_folder_names.len()
        );

        let is_shared;
        if my_mt.encrypted_shared_folder_names.len() != 0 {
            let go_shared: String = input()
                .repeat_msg("Do you want to look at your shared folder(s)? \n[y/n]: ")
                .add_test(|x| *x == "yes" || *x == "y" || *x == "no" || *x == "n")
                .get();

            match go_shared.as_str() {
                "yes" | "y" => is_shared = true,
                "no" | "n" => is_shared = false, //il y a surement un moyen plus élégant que si oui vrai si non faux
                _ => panic!("an unexpected answer was given."),
            }
        } else {
            is_shared = false;
        }

        if is_shared {
            println!("This operation may take a long time, please be patient ...");
            let mut my_decrypted_shared_foldernames: Vec<String> = Vec::new();

            for i in 0..my_mt.encrypted_shared_folder_names.len() {
                let loop_owner_pk =
                    server.ask_for_public_key(my_mt.shared_folder_owner[i].as_str());
                let folder_name = self.decipher_asym_text(
                    my_mt.encrypted_shared_folder_names[i].0.as_str(),
                    &loop_owner_pk,
                    my_mt.encrypted_shared_folder_names[i].1.as_str(),
                );

                let result = format!("{}:{}", my_mt.shared_folder_owner[i], folder_name);
                my_decrypted_shared_foldernames.push(result);
            }

            let (index, is_folder) = self.handle_file_choice(
                &Vec::<String>::new(),
                &my_decrypted_shared_foldernames,
                false,
            );

            if !is_folder {
                panic!("imposible choice!");
            }
            let owner_pk = server.ask_for_public_key(my_mt.shared_folder_owner[index].as_str());
            let decrypted_shared_keys = self.decipher_asym_key(
                my_mt.encrypted_shared_folder_keys[index].0.as_str(),
                &owner_pk,
                my_mt.encrypted_shared_folder_keys[index].1.as_str(),
            );
            let shared_folder_name = my_mt.shared_folder_names_hash[index].clone();
            folder_hash_and_key = (shared_folder_name, decrypted_shared_keys);
        } else {
            // we load root
            let root_name_hash = my_mt.encrypted_root_name_hash.clone();
            let root_folder = server.ask_for_folder(root_name_hash.as_str());

            let my_decrypted_root_key = self.decipher_sym_key(
                root_folder.encrypted_folder_key.as_str(),
                root_folder.folder_key_nonce.as_str(),
                &Client::to_sym_key(&self.master_key.unwrap()),
            );

            folder_hash_and_key = (root_name_hash, my_decrypted_root_key);
        }

        //let mut my_decrypted_filenames: Vec<String> = Vec::new();

        /*
        for encrypted_filename in &my_mt.encrypted_filenames {
            // this is really badly optimised, as key, nonce and salt have to be retrieved each time
            my_decrypted_filenames.push(self.decrypt_stuff(
                encrypted_filename,
                my_mt.user_salt.as_str(),
                my_mt.user_nonce.as_str(),
            ))
        }*/

        self.file_and_folder_loop(
            server,
            folder_hash_and_key.0.as_str(),
            &folder_hash_and_key.1,
        );
        println!("You escaped the recursion, good job, the program will now stop normally.");
    }
    /**
     * Is the true main loop once in a root folder
     */
    fn file_and_folder_loop(
        &self,
        server: &Server,
        folder_hash: &str,
        folder_key: &secretbox::Key,
    ) {
        let my_folder = server.ask_for_folder(folder_hash);
        loop {
            println!("");
            println!("");

            let mut file_name_vec: Vec<String> = Vec::new();
            let mut folder_name_vec: Vec<String> = Vec::new();

            for i in 0..my_folder.encrypted_file_names.len() {
                let deciphered_file_name = self.decipher_sym_text(
                    my_folder.encrypted_file_names[i].as_str(),
                    my_folder.file_name_nonces[i].as_str(),
                    folder_key,
                );
                let result = format!("{}:{}", my_folder.owner, deciphered_file_name);
                file_name_vec.push(result);
            }
            for i in 0..my_folder.encrypted_folder_names.len() {
                let deciphered_folder_name = self.decipher_sym_text(
                    my_folder.encrypted_folder_names[i].as_str(),
                    my_folder.folder_name_nonces[i].as_str(),
                    folder_key,
                );
                let result = format!("{}:{}", my_folder.owner, deciphered_folder_name);
                folder_name_vec.push(result);
            }

            let my_choice = self.handle_file_choice(&file_name_vec, &folder_name_vec, true);

            if my_choice.1 {
                // we got a folder -> recursion or go back a folder
                if my_choice.0 == folder_name_vec.len() {
                    println!("You chose to go back a folder.");
                    break; // we go back a folder
                }
                // we load choice.0
                let choice_folder_name_hash =
                    my_folder.encrypted_folder_names_hash[my_choice.0].as_str();
                let choice_folder = server.ask_for_folder(choice_folder_name_hash);
                let decrypted_choice_folder_key = self.decipher_sym_key(
                    choice_folder.encrypted_folder_key.as_str(),
                    choice_folder.folder_key_nonce.as_str(),
                    folder_key,
                );

                // recursion time
                self.file_and_folder_loop(
                    server,
                    choice_folder_name_hash,
                    &decrypted_choice_folder_key,
                );
            } else {
                // we got a file -> load file
                // we need to load: my_choice.0
                let choice_file_name_hash =
                    my_folder.encrypted_file_names_hash[my_choice.0].as_str();
                let choice_file = server.ask_for_file(choice_file_name_hash);

                let my_deciphered_file = self.decipher_sym_text(
                    choice_file.encrypted_data.as_str(),
                    choice_file.file_nonce.as_str(),
                    folder_key,
                );
                println!("Here is your file:\n{}", my_deciphered_file);
            }
        }
    }

    /// static method

    /**
     * # returns
     * usize is the index of the file or folder
     * bool is true if we want a folder
     * if we can go back a folder then, size + 1 is that option in usize for folder
     */
    fn handle_file_choice(
        &self,
        decrypted_filenames: &Vec<String>,
        decrypted_foldernames: &Vec<String>,
        can_go_back_a_folder: bool, // if true add an option to leave folder
    ) -> (usize, bool) {
        let is_folder_chosen: bool;

        println!(
            "This folder has {} file(s) and {} folder(s)",
            decrypted_filenames.len(),
            decrypted_foldernames.len()
        );
        if can_go_back_a_folder {
            println!("You may go back a folder.");
        }

        if decrypted_filenames.len() == 0 && decrypted_foldernames.len() == 0 {
            if !can_go_back_a_folder {
                panic!("Congratulation, root is empty, you found the easter egg)!");
                // how to disguise a failure into a win
            }
            println!("This folder is empty.");
            return (1, true); // auto go back one folder
        } else {
            let mut i: usize = 0;
            if decrypted_filenames.len() != 0 {
                println!("Files:");
                for filename in decrypted_filenames {
                    i += 1;
                    println!("{} # {}", i, filename);
                }
            } // todo other stuff here
            let mut i: usize = 0; // thx rust
            println!("Folders:");
            for foldername in decrypted_foldernames {
                i += 1;
                println!("{} # {}", i, foldername);
            }
            if can_go_back_a_folder {
                i += 1;
                println!("{} # Go back a folder.", i);
            }
        }

        let file_folder: String = input()
            .repeat_msg("Do you want to select a file or a folder? \n[file/folder]: ")
            .add_test(|x| *x == "file" || *x == "folder")
            .get();

        match file_folder.as_str() {
            "file" => is_folder_chosen = false,
            "folder" => is_folder_chosen = true, //il y a surement un moyen plus élégant que si oui vrai si non faux
            _ => panic!("an unexpected answer was given."),
        }

        if !is_folder_chosen {
            let mut message = String::from("Select the file you want to read/download.\n");

            let mut i: usize = 0;
            println!("Files:");
            for filename in decrypted_filenames {
                i += 1;
                message.push_str(format!("{} # {}\n", i, filename).as_str());
            }
            message.push_str("Choice: ");

            let choice: usize = input()
                .repeat_msg(message)
                .err(format!("Please enter a number in the range [1:{}].", i))
                .add_test(move |x| *x <= i && *x != 0)
                .get();
            println!("Your choice is: {}", choice);
            return (choice - 1, false);
        } else {
            // folder
            let mut message = String::from("Select the folder you want to go to.\n");

            let mut i: usize = 0;
            println!("Folders:");
            for foldername in decrypted_foldernames {
                i += 1;
                message.push_str(format!("{} # {}\n", i, foldername).as_str());
            }
            if can_go_back_a_folder {
                i += 1;
                message.push_str(format!("{} # Go back a folder.\n", i).as_str());
            }
            message.push_str("Choice: ");

            let choice: usize = input()
                .repeat_msg(message)
                .err(format!("Please enter a number in the range [1:{}].", i))
                .add_test(move |x| *x <= i && *x != 0)
                .get();
            println!("Your choice is: {}", choice);
            return (choice - 1, true);
        }
    }
    /// static method
    pub fn entrypoint() -> () {
        let username: String = input().msg("Please enter your Username.\nUsername: ").get();
        let master_password: String = input().msg("Please enter your password.\nPassword: ").get();
        let mut client = Client::new(username.clone(), master_password);

        println!("We will now connect to the server. Please wait a moment.");

        let mut connected_server = Server::connection();

        let (challenge, key, nonce, salt) = connected_server.send_challenge(username);

        client.load_master_key(salt.as_str());
        client.load_key_pair();

        let my_str: String;
        match client.answer_challenge(challenge, &nonce, &key) {
            Ok(s) => my_str = s,
            Err(e) => {
                println!("{}", e);
                return;
            }
        }

        match connected_server.is_answer_accepted(my_str) {
            true => println!("Challenge passed, connection established."),
            false => {
                println!("Challenge failed, connection has been cut.");
                return;
            }
        }

        client.handle_exchange(&connected_server);
    }
}
