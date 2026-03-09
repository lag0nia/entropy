const std = @import("std");

pub const BIP39_WORD_COUNT = 2048;
pub const ENTROPY_BYTES = 16; // 128 bits -> 12 words
pub const MNEMONIC_WORDS = 12;

pub const Bip39Error = error{
    WordlistLoadFailed,
    InvalidWordlistSize,
};

/// Load the BIP-39 English wordlist from file.
/// Caller owns the returned memory.
pub fn loadWordlist(allocator: std.mem.Allocator, path: []const u8) ![][]const u8 {
    const file = std.fs.cwd().openFile(path, .{ .mode = .read_only }) catch
        return Bip39Error.WordlistLoadFailed;
    defer file.close();

    const data = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(data);

    var words: std.ArrayList([]const u8) = .{};
    errdefer {
        for (words.items) |word| {
            allocator.free(word);
        }
        words.deinit(allocator);
    }

    var it = std.mem.tokenizeScalar(u8, data, '\n');
    while (it.next()) |word| {
        const trimmed = std.mem.trim(u8, word, " \t\r");
        if (trimmed.len > 0) {
            const owned_word = try allocator.dupe(u8, trimmed);
            try words.append(allocator, owned_word);
        }
    }

    if (words.items.len != BIP39_WORD_COUNT) {
        return Bip39Error.InvalidWordlistSize;
    }

    return words.toOwnedSlice(allocator);
}

pub fn freeWordlist(allocator: std.mem.Allocator, wordlist: [][]const u8) void {
    for (wordlist) |word| {
        allocator.free(word);
    }
    allocator.free(wordlist);
}

/// Generate a 12-word BIP-39 mnemonic.
///
/// Algorithm (per BIP-39 spec):
/// 1. Generate 128 bits (16 bytes) of cryptographic entropy
/// 2. SHA-256 hash the entropy; take first 4 bits as checksum
/// 3. Append checksum to entropy -> 132 bits total
/// 4. Split into 12 groups of 11 bits -> 12 indices (0..2047)
/// 5. Map each index to the corresponding word in the wordlist
pub fn generateMnemonic(
    allocator: std.mem.Allocator,
    wordlist: []const []const u8,
    separator: []const u8,
) ![]const u8 {
    // Step 1: Generate 128 bits of entropy
    var entropy: [ENTROPY_BYTES]u8 = undefined;
    std.crypto.random.bytes(&entropy);

    return mnemonicFromEntropy(allocator, &entropy, wordlist, separator);
}

/// Generate mnemonic from a specific entropy (useful for testing with known vectors)
pub fn mnemonicFromEntropy(
    allocator: std.mem.Allocator,
    entropy: *const [ENTROPY_BYTES]u8,
    wordlist: []const []const u8,
    separator: []const u8,
) ![]const u8 {
    // Step 2: SHA-256 hash -> take first 4 bits as checksum
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(entropy, &hash, .{});
    const checksum_bits: u4 = @truncate(hash[0] >> 4);

    // Step 3: Build 132-bit value (128 bits entropy + 4 bits checksum)
    // We'll extract 11-bit groups to get word indices
    //
    // We work with the entropy bytes + checksum packed into the bit stream:
    //   bit 0..127  = entropy
    //   bit 128..131 = checksum (4 bits)

    var words = try allocator.alloc([]const u8, MNEMONIC_WORDS);
    defer allocator.free(words);

    var i: usize = 0;
    while (i < MNEMONIC_WORDS) : (i += 1) {
        const bit_offset = i * 11;
        const index = extractBits(entropy, checksum_bits, bit_offset);
        words[i] = wordlist[index];
    }

    // Join with separator
    return std.mem.join(allocator, separator, words);
}

/// Extract 11 bits starting at `bit_offset` from the 132-bit stream
/// (128 bits of entropy + 4 bits of checksum).
fn extractBits(entropy: *const [ENTROPY_BYTES]u8, checksum: u4, bit_offset: usize) u16 {
    var value: u16 = 0;
    var bit: usize = 0;
    while (bit < 11) : (bit += 1) {
        const pos = bit_offset + bit;
        const b: u1 = if (pos < 128) blk: {
            // From entropy bytes
            const byte_idx = pos / 8;
            const bit_idx: u3 = @intCast(7 - (pos % 8));
            break :blk @truncate(entropy[byte_idx] >> bit_idx);
        } else blk: {
            // From checksum (bits 128..131)
            const checksum_bit_idx: u2 = @intCast(3 - (pos - 128));
            break :blk @truncate(@as(u4, checksum) >> checksum_bit_idx);
        };
        value = (value << 1) | b;
    }
    return value;
}

test "BIP-39 known test vector" {
    // BIP-39 test vector:
    // entropy (hex): 00000000000000000000000000000000
    // expected mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    const allocator = std.testing.allocator;
    _ = allocator;

    // We need the wordlist for this test - create a minimal inline test
    // Using the known result: all-zero entropy should produce index 0 repeated 11 times,
    // then index for the checksum-derived last word.
    const entropy = [_]u8{0} ** ENTROPY_BYTES;

    // SHA256 of 16 zero bytes: the first byte determines checksum
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&entropy, &hash, .{});
    const expected_checksum: u4 = @truncate(hash[0] >> 4);

    // First 11 bits of all zeros = 0, so first 11 words should map to index 0
    // Last word: bits 121..131 = 7 bits of zero from entropy + 4 bits checksum
    // = 0000000 ++ checksum(4 bits) = checksum << 0 (effectively the checksum value)

    // Verify extractBits for first word
    const idx0 = extractBits(&entropy, expected_checksum, 0);
    try std.testing.expectEqual(@as(u16, 0), idx0);
}

test "extractBits basic" {
    // All zeros entropy, checksum = 0 -> all indices should be 0
    const entropy = [_]u8{0} ** ENTROPY_BYTES;
    const checksum: u4 = 0;

    var i: usize = 0;
    while (i < MNEMONIC_WORDS) : (i += 1) {
        const idx = extractBits(&entropy, checksum, i * 11);
        try std.testing.expectEqual(@as(u16, 0), idx);
    }
}

test "extractBits all ones" {
    // All 0xFF entropy
    const entropy = [_]u8{0xFF} ** ENTROPY_BYTES;
    const checksum: u4 = 0xF;

    // Every 11-bit group of all-ones = 2047
    var i: usize = 0;
    while (i < MNEMONIC_WORDS) : (i += 1) {
        const idx = extractBits(&entropy, checksum, i * 11);
        try std.testing.expectEqual(@as(u16, 2047), idx);
    }
}
