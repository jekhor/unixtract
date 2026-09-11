//MSD OUITH parsers
pub mod msd_ouith_parser_old;
pub mod msd_ouith_parser_tizen_1_8;
pub mod msd_ouith_parser_tizen_1_9;

use sha2::{Digest, Sha256};

use crate::utils::aes::{decrypt_aes128_cbc_pcks7, decrypt_aes256_cbc_pcks7};

pub fn decrypt_aes_salted_old(encrypted_data: &[u8], passphrase_bytes: &Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if &encrypted_data[0..8] != b"Salted__" {
        return Err("Invalid encrypted data!".into());
    }
    let salt = &encrypted_data[8..16];

    //key = md5 of (passphrase + salt)
    let mut key = Vec::new();
    key.extend_from_slice(&passphrase_bytes);
    key.extend_from_slice(&salt);
    let key_md5 = md5::compute(&key).0;

    //iv = md5 of (md5 of key + passphrase + salt)
    let mut iv = Vec::new();
    iv.extend_from_slice(&key_md5);
    iv.extend_from_slice(&passphrase_bytes);
    iv.extend_from_slice(&salt);
    let iv_md5 = md5::compute(&iv).0;

    decrypt_aes128_cbc_pcks7(&encrypted_data[16..], &key_md5, &iv_md5)
}

pub fn decrypt_aes_salted_tizen(encrypted_data: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if &encrypted_data[0..8] != b"Salted__" {
        return Err("Invalid encrypted data!".into());
    }
    let salt = &encrypted_data[8..16];
    
    if passphrase.len() == 16 { //aes128, md5 deviration
        let iv = md5::compute(salt).0;
        return decrypt_aes128_cbc_pcks7(&encrypted_data[16..], &passphrase.try_into().unwrap(), &iv);

    } else if passphrase.len() == 32 { //aes256, sha256 deviration
        let digest: [u8; 32] = Sha256::digest(salt).into();
        let iv: [u8; 16] = digest[..16].try_into().unwrap();
        return decrypt_aes256_cbc_pcks7(&encrypted_data[16..], &passphrase.try_into().unwrap(), &iv);
            
    } else {
        return Err("Invalid passphrase lenght".into())
    };
}

pub fn decrypt_aes_tizen(encrypted_data: &[u8], passphrase: &[u8], salt: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if passphrase.len() == 16 { //aes128, md5 deviration
        let iv = md5::compute(salt).0;
        return decrypt_aes128_cbc_pcks7(&encrypted_data, &passphrase.try_into().unwrap(), &iv);

    } else if passphrase.len() == 32 { //aes256, sha256 deviration
        let digest: [u8; 32] = Sha256::digest(salt).into();
        let iv: [u8; 16] = digest[..16].try_into().unwrap();
        return decrypt_aes256_cbc_pcks7(&encrypted_data, &passphrase.try_into().unwrap(), &iv);
            
    } else {
        return Err("Invalid passphrase lenght".into())
    };
}

pub fn is_valid_ouith(data: &[u8]) -> bool{
    return &data[256..306] == b"Tizen Software Upgrade Tree Binary Format ver. 1.8" || 
           &data[262..312] == b"Tizen Software Upgrade Tree Binary Format ver. 1.9" ||
           &data[518..568] == b"Tizen Software Upgrade Tree Binary Format ver. 1.9"       //new signature ver
}

pub fn is_valid_ouith_old(data: &[u8]) -> bool{
    if data.len() < 128+8 {
        return false;
    }
    //sanity check 1: size of first chunk header smaller than data size
    if u32::from_be_bytes(data[128..132].try_into().unwrap()) > data.len() as u32 {
        return false;
    }
    
    //sanity check 2: top level descriptor. it can only be ID 1(OUUpgradeItemDesc) or 2(OUGroupDesc)
    let v = u16::from_be_bytes(data[136/* signature(128) + chunk header(8) */..138].try_into().unwrap());
    return v == 0x01 || v == 0x02;
}