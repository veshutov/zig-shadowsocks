const std = @import("std");
const crypto = std.crypto;
const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;

const PASSWORD = "your-password-here";
const MASTER_KEY_SIZE = 32;
const SUBKEY_CONTEXT = "ss-subkey";
const SUBKEY_SIZE = 32;
const NONCE_SIZE = 12;

pub const SALT_SIZE = 32;
pub const TAG_SIZE = 16;
pub const PAYLOAD_LENGTH_SIZE = 2;
pub const MAX_PAYLOAD_SIZE = 16 * 1024 - 1;

pub const DecryptResult = struct { ciphertext_read: usize, plaintext_written: usize };

pub const Encryptor = struct {
    salt: [SALT_SIZE]u8,
    subkey: [SUBKEY_SIZE]u8 = undefined,
    nonce: [NONCE_SIZE]u8 = std.mem.zeroes([NONCE_SIZE]u8),

    pub fn init(self: *Encryptor) void {
        generateSessionSubkey(&self.salt, &self.subkey);
    }

    pub fn decrypt(self: *Encryptor, ciphertext: []const u8, plaintext: []u8) !usize {
        const data_len = ciphertext.len - TAG_SIZE;
        const data = ciphertext[0..data_len];
        const tag = ciphertext[data_len..][0..TAG_SIZE];

        try ChaCha20Poly1305.decrypt(plaintext[0..data_len], data, tag.*, &[_]u8{}, self.nonce, self.subkey);

        self.incrementNonce();

        return data_len;
    }

    pub fn decryptLength(self: *Encryptor, ciphertext: []const u8, plaintext: []u8) !DecryptResult {
        const payload_length_data = ciphertext[0 .. PAYLOAD_LENGTH_SIZE + TAG_SIZE];
        _ = try self.decrypt(payload_length_data, plaintext);

        return .{
            .ciphertext_read = PAYLOAD_LENGTH_SIZE + TAG_SIZE,
            .plaintext_written = PAYLOAD_LENGTH_SIZE,
        };
    }

    pub fn decryptChunk(self: *Encryptor, ciphertext: []const u8, plaintext: []u8) !DecryptResult {
        const payload_length_data = ciphertext[0 .. PAYLOAD_LENGTH_SIZE + TAG_SIZE];
        var payload_length_buf: [PAYLOAD_LENGTH_SIZE]u8 = undefined;
        _ = try self.decrypt(payload_length_data, payload_length_buf[0..]);
        const payload_length = std.mem.readInt(u16, &payload_length_buf, .big);

        const payload_start = payload_length_data.len;
        const payload_end = payload_start + payload_length + TAG_SIZE;
        const payload_data = ciphertext[payload_start..payload_end];
        _ = try self.decrypt(payload_data, plaintext);

        return .{
            .ciphertext_read = payload_length_data.len + payload_data.len,
            .plaintext_written = payload_length,
        };
    }

    pub fn encrypt(self: *Encryptor, plaintext: []const u8, ciphertext: []u8) usize {
        const data = ciphertext[0..plaintext.len];
        const tag = ciphertext[plaintext.len..][0..TAG_SIZE];
        @memcpy(data, plaintext);

        ChaCha20Poly1305.encrypt(data, tag, plaintext, &[_]u8{}, self.nonce, self.subkey);

        self.incrementNonce();
        return plaintext.len + TAG_SIZE;
    }

    fn incrementNonce(self: *Encryptor) void {
        var carry: u16 = 1;
        for (0..self.nonce.len) |i| {
            carry += self.nonce[i];
            self.nonce[i] = @truncate(carry);
            carry >>= 8;
            if (carry == 0) break;
        }
    }
};

fn generateSessionSubkey(salt: []const u8, subkey: []u8) void {
    var master_key: [MASTER_KEY_SIZE]u8 = undefined;
    evpBytesToKey(PASSWORD, &master_key);

    const hkdf = crypto.kdf.hkdf.Hkdf(crypto.auth.hmac.HmacSha1);
    const prk = hkdf.extract(salt, master_key[0..]);
    hkdf.expand(subkey, SUBKEY_CONTEXT, prk);
}

fn evpBytesToKey(password: []const u8, key: []u8) void {
    var hasher = crypto.hash.Md5.init(.{});
    var result: [16]u8 = undefined;
    var key_len: usize = 0;

    // First round
    hasher.update(password);
    hasher.final(&result);
    const copy_len1 = @min(result.len, key.len);
    @memcpy(key[0..copy_len1], result[0..copy_len1]);
    key_len += copy_len1;

    // Second round if we need more bytes
    if (key_len < key.len) {
        hasher = crypto.hash.Md5.init(.{});
        hasher.update(&result);
        hasher.update(password);
        hasher.final(&result);
        const remaining = key.len - key_len;
        const copy_len2 = @min(result.len, remaining);
        @memcpy(key[key_len .. key_len + copy_len2], result[0..copy_len2]);
    }
}
