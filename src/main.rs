mod client;
mod constant;
mod file_n_metadata;
mod server;
mod vault;
use read_input::prelude::*;


use vault::Vault;
use client::Client;

fn main() {
    let my_s : String = input()
    .repeat_msg("Do you want to initialize/reinitialize the database?\n[y/n]: ")
    .add_test(|x| *x == "yes" || *x == "y" || *x == "no" || *x == "n")
    .get();
    
    match my_s.as_str(){
        "yes" | "y" => Vault::create_default_db(),
        "no" | "n" => (),
        _ => panic!("an unexpected answer was given."),
    }
    Client::entrypoint();
}
