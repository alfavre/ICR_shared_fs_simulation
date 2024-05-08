# ICR_shared_fs_simulation
## Author 
```
Alban Favre
```
### Intro

This is a practical rust work for school.
This is done for the 2024 second semester of HES-SO's master ICR course.

### Objectives

Implement a secure file system, that allows file sharing

**warning**:
- the KDF needs to be fast, we don't want to stop bruteforce
- The shared system idea is that a "folder" is just a special file that is the key of the file in the folder

### Report

This file is **NOT** the report,
the real report can be found in `doc/report.md` or `doc/report.pdf`

### Understanding

**WARNING, OLD, TO C**

there is three entities: the `client`, the `server` and the `vault`

the server is just a bridge between the two, when a client is authenticated it can ask for encrypted file, that will have to be decrypted by itself.

The password is a master key, capable of answering challenges, decrypting the file list and deriving each key for each file. The hard coded password is `4KL7g#.7c,HMPRrZ` and can be foun in `src/constant.rs`

### Checkmarks

- [X] client side
  - [X] client has only one password
  - [X] client can answer challenges
  - [X] client can decrypt filenames list
  - [X] client can ask for a file
  - [X] client can decrypt file
- [X] server side
  - [X] server can ask challenges
  - [X] server can fetch encrypted filename list
  - [X] server can fetch encrypted file
- [X] vault side
  - [X] vault stores encrypted filenames
  - [X] vault stores encrypted files

### Possible Bonuses (Boni ?)

- [X] server can work with multiple user
  - [X] server cant distinguish between user file (aka which file is to whomst)
- [ ] file sharing among user ???
  - [ ] what ???
- [ ] multi factor auth
  - [ ] just cc from sec
- [ ] use TPM to secure secrets
  - [ ] what?
- [ ] and more

### Notes

Everything will be simulated (database, server, communications)

### Help for my poor brain

```rust
    pub fn slice_to_string(slice: &[u8]) -> String {
        String::from(std::str::from_utf8(&slice).unwrap())
    }

    pub fn string_to_slice(string: &str) -> &[u8] {
        // might cause lifetime problems
        string.as_bytes()
    }

    pub fn vec_to_string(vec: Vec<u8>) -> String {
        String::from_utf8(vec).unwrap()
    }

    pub fn vec_to_slice<'a>(vec: Vec<u8>) -> () {
        // might cause lifetime problems
        println!("dont call this method");
        //&vec
    }
```
