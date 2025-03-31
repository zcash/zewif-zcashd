use zewif::blob;

pub const NOTEPLAINTEXT_LEADING: usize = 1;
pub const V_SIZE: usize = 8;
pub const R_SIZE: usize = 32;
pub const RHO_SIZE: usize = 32;
pub const MEMO_SIZE: usize = 512;
pub const NOTEPLAINTEXT_SIZE: usize =
    NOTEPLAINTEXT_LEADING + V_SIZE + RHO_SIZE + R_SIZE + MEMO_SIZE;
pub const MLEN: usize = NOTEPLAINTEXT_SIZE;
pub const NOTEENCRYPTION_AUTH_BYTES: usize = 16;
pub const CLEN: usize = MLEN + NOTEENCRYPTION_AUTH_BYTES;

blob!(NoteEncryptionCiphertext, CLEN, "A ciphertext for a note encryption in Zcash transactions.");
