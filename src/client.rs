use super::*;
use read_input::prelude::*;
use server::Server;
use sodiumoxide::base64::*;
use sodiumoxide::crypto::*;

pub struct Client {
    master_password: String,
    username: String,
    master_key: Option<[u8;32]>,
    pk:Option<box_::PublicKey>,
    sk:Option<box_::SecretKey>,
}

impl Client {
    fn new(username: String, master_password: String) -> Client {
        Client {
            master_password: master_password,
            username: username,
            master_key: None,
            pk: None,
            sk: None,
        }
    }

    fn answer_challenge(&self, b64_nonce: &str) -> String {
        let digest_pass = hash::hash(self.master_password.as_bytes());
        let shared_secret = encode(digest_pass, Variant::UrlSafe);

        let mut hash_state = hash::State::new();
        hash_state.update(shared_secret.as_bytes());
        hash_state.update(b64_nonce.as_bytes());
        let answer = hash_state.finalize();

        encode(answer, Variant::UrlSafe)
    }

    fn load_master_key(&mut self,b64_salt: &str, passphrase: &str) -> () {

        let my_salt_slice = decode(b64_salt, Variant::UrlSafe).unwrap();
        let my_salt = pwhash::Salt::from_slice(&my_salt_slice).unwrap();

        let mut kx = secretbox::Key([0; secretbox::KEYBYTES]);
        let secretbox::Key(ref mut my_key) = kx;
        pwhash::derive_key(
            my_key,                // this is where the result is stored, à la C
            passphrase.as_bytes(), // we derive passphrase here
            &my_salt,
            pwhash::OPSLIMIT_INTERACTIVE,
            pwhash::MEMLIMIT_INTERACTIVE,
        ).unwrap();
         // unwrap just in case we get an error, in which case it should panic

        self.master_key = Some(*my_key);
    }

    fn load_key_pair(&mut self) -> () {
        // make key pair from master password
        let public_key;
        let secret_key;
        let box_seed = box_::Seed::from_slice(&self.master_key.expect("master key not yet loaded")).unwrap();
        (public_key, secret_key) = box_::keypair_from_seed(&box_seed);
        self.sk = Some(secret_key);
        self.pk = Some(public_key);
    }

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
    }

    fn get_pt_hash_in_b64(&self, pt_filename: &str) -> String {
        let mut hash_state = hash::State::new();
        hash_state.update(self.master_password.as_bytes());
        hash_state.update(pt_filename.as_bytes());
        let digest = hash_state.finalize();

        encode(digest, Variant::UrlSafe)
    }

    fn handle_exchange(&mut self, server: Server) {
        /*
        println!("We will fetch the list of all your files, please wait a moment.");

        let my_metadata = server.ask_for_metadata(); // this will never leave this scope in theory

        let mut my_decrypted_filenames: Vec<String> = Vec::new();

        for encrypted_filename in &my_metadata.encrypted_filenames {
            // this is really badly optimised, as key, nonce and salt have to be retrieved each time
            my_decrypted_filenames.push(self.decrypt_stuff(
                encrypted_filename,
                my_metadata.user_salt.as_str(),
                my_metadata.user_nonce.as_str(),
            ))
        }

        loop {
            let my_choice = Client::handle_file_choice(&my_decrypted_filenames);

            println!("We will fetch your file, please wait a moment.");

            let my_b64_pt_hash =
                self.get_pt_hash_in_b64(my_decrypted_filenames[my_choice].as_str());

            let my_enc_file = server.ask_for_specific_file_with_pt_hash(my_b64_pt_hash.as_str());

            let my_dec_file = self.decrypt_stuff(
                my_enc_file.encrypted_data.as_str(),
                my_enc_file.file_salt.as_str(),
                my_enc_file.file_nonce.as_str(),
            );

            println!("Here is your file:\n{}", my_dec_file);
        }*/
    }

    /// static method
    fn handle_file_choice(decrypted_filenames: &Vec<String>) -> usize {
        let mut message = String::from("Select the file you want to read/download.\n");
        let mut i: usize = 1;
        for s in decrypted_filenames {
            message.push_str(format!("{}:\t", i).as_str());
            message.push_str(s.as_str());
            message.push_str("\n");
            i += 1;
        }
        message.push_str("Choice: ");

        let choice: usize = input()
            .repeat_msg(message)
            .err(format!(
                "Please enter a number in the range [1:{}].",
                (i - 1)
            ))
            .add_test(move |x| *x <= (i - 1) && *x != 0)
            .get();

        choice - 1 // :)
    }

    pub fn entrypoint() -> () {
        let username: String = input().msg("Please enter your Username.\nUsername: ").get();
        let master_password: String = input().msg("Please enter your password.\nPassword: ").get();
        let mut client = Client::new(username, master_password);

        println!("We will now connect to the server. Please wait a moment.");

        let mut connected_server = Server::connection();

        let (challenge, key, nonce, salt) = connected_server.send_challenge(username);

        client.load_master_key(salt.as_str(), master_password.as_str());

        match connected_server.is_answer_accepted(client.answer_challenge(challenge.as_str())) {
            true => println!("Challenge passed, connection established."),
            false => {
                println!("Challenge failed, connection has been cut.");
                return;
            }
        }

        client.handle_exchange(connected_server);
    }
}
