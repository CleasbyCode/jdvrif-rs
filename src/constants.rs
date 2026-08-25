pub(crate) const INFO_TEXT: &str = r#"

JPG Data Vehicle (jdvrif v9.0)
Created by Nicholas Cleasby (@CleasbyCode) 10/04/2023

jdvrif is a metadata "steganography-like" command-line tool used for concealing and extracting
any file type within and from a JPG image.

──────────────────────────
Build & run (Linux only)
──────────────────────────

  Note: Linux only. Rust toolchain required (install via https://rustup.rs).

  $ sudo apt install g++ libsodium-dev libturbojpeg0-dev libjpeg-dev pkg-config
  $ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  $ cargo build --release

  $ sudo cp target/release/jdvrif-rs /usr/bin
  $ jdvrif-rs

──────────────────────────
Usage
──────────────────────────

  jdvrif-rs conceal [-b|-r] <cover_image> <secret_file>
  jdvrif-rs recover <cover_image>
  jdvrif-rs --info

──────────────────────────
Platform compatibility & size limits
──────────────────────────

Share your "file-embedded" JPG image on the following compatible sites.

Platforms where size limit is measured by the combined size of cover image + compressed data file:

	• Flickr    (200 MB)
	• ImgPile   (100 MB)
	• ImgBB     (32 MB)
	• PostImage (32 MB)
	• Pixelfed  (15 MB)

Limit measured by compressed data file size only:

	• Mastodon  (~6 MB)
	• Tumblr    (~64 KB)
	• X-Twitter (~10 KB)

For example, on Mastodon, even if your cover image is 1 MB, you can still embed a data file
up to the ~6 MB Mastodon size limit.

Other:

Bluesky - (use -b option). The finished "file-embedded" JPG must not exceed 2,000,000 bytes,
so the cover image and the compressed data file share one combined budget:

	• Cover image + compressed data file: 2,000,000 bytes combined
	• Compressed data file on its own:    ~171 KB

A cover image already at 2,000,000 bytes leaves no room for a payload, so keep the cover
smaller than 2,000,000 bytes by at least the size of the compressed data file.

Reddit - (use -r option). Cover and payload input files must each be no larger than 20 MiB.
The cover is transcoded to baseline Q75/4:2:0, and the theoretical C3 payload limit is
calculated from its luminance DCT blocks after transcoding.

Even though jdvrif compresses the data file, you may want to compress it yourself first
(zip, rar, 7z, etc.) so that you know the exact compressed file size.

Platforms with small size limits, like X-Twitter (~10 KB), are best suited for data that
compress especially well, such as text files.

──────────────────────────
Modes
──────────────────────────

conceal - *Compresses, encrypts and embeds your secret data file within a JPG cover image.
recover - Decrypts, uncompresses and extracts the concealed data file from a JPG cover image
          (recovery PIN required).

(*Compression: If data file is already a compressed file type (based on file extension: e.g. ".zip")
 and the file is greater than 10MB, skip compression).

──────────────────────────
Platform options for conceal mode
──────────────────────────

-b (Bluesky) : Creates compatible "file-embedded" JPG images for posting on Bluesky.

$ jdvrif-rs conceal -b my_image.jpg hidden.doc

These images are only compatible for posting on Bluesky.

You must use the Python script "bsky/create_bsky_post.py" (in the repo's src folder) to post to Bluesky.
Posting via the Bluesky website or mobile app will NOT work.

You also need to create an app password for your Bluesky account: https://bsky.app/settings/app-passwords

Set your credentials as environment variables. This keeps the app password out of the command line,
where it would be visible to other local users via tools such as ps:

  $ export ATP_AUTH_HANDLE='you.bsky.social'
  $ read -rsp 'Bluesky app password: ' ATP_AUTH_PASSWORD && export ATP_AUTH_PASSWORD
  $ printf '\n'

Here are some basic usage examples for the create_bsky_post.py Python script:

Standard image post to your profile/account.

$ python3 bsky/create_bsky_post.py \
    --image your_image.jpg \
    --alt-text "alt-text here [optional]" \
    "standard post text here [required]"

If you want to post multiple images (Max. 4):

$ python3 bsky/create_bsky_post.py \
    --image img1.jpg \
    --alt-text "alt text for image 1" \
    --image img2.jpg \
    --alt-text "alt text for image 2" \
    "standard post text..."

If you want to post an image as a reply to another thread:

$ python3 bsky/create_bsky_post.py \
    --image your_image.jpg \
    --alt-text "alt_here" \
    --reply-to https://bsky.app/profile/someone.bsky.social/post/8m2tgw6cgi23i \
    "standard post text..."

After posting, remove the app password from the current shell with:

  $ unset ATP_AUTH_PASSWORD

Bluesky size limits: cover image + compressed data file must total no more than 2,000,000
bytes, and the compressed data file alone must not exceed ~171 KB.

-r (Reddit) : Creates a baseline Q75/4:2:0 JPG with an encrypted C3 DCT payload for Reddit.

$ jdvrif-rs conceal -r my_image.jpg hidden.doc

These images are only compatible for posting on Reddit. The program displays the exact
theoretical carrier limit for each transcoded cover image.

To correctly download images from X-Twitter, click image within the post to fully expand it before saving.

"#;

pub(crate) const NO_ZLIB_COMPRESSION_ID: u8 = 0x58;
pub(crate) const NO_ZLIB_COMPRESSION_ID_INDEX: usize = 0x80;

pub(crate) const MAX_FILE_SIZE: u64 = 3 * 1024 * 1024 * 1024;
pub(crate) const MINIMUM_IMAGE_SIZE: u64 = 134;
pub(crate) const MAX_IMAGE_SIZE: u64 = 8 * 1024 * 1024;
pub(crate) const REDDIT_UPLOAD_SIZE_LIMIT: usize = 20 * 1024 * 1024;

pub(crate) const WRITE_COMPLETE_ERROR: &str = "Write Error: Failed to write complete output file.";
pub(crate) const CORRUPT_FILE_ERROR: &str = "File Extraction Error: Embedded data file is corrupt!";

pub(crate) const JDVRIF_SIG: [u8; 7] = [0xB4, 0x6A, 0x3E, 0xEA, 0x5E, 0x9D, 0xF9];
pub(crate) const ICC_PROFILE_SIG: [u8; 7] = [0x6D, 0x6E, 0x74, 0x72, 0x52, 0x47, 0x42];

// Layout of the 56-byte KDF metadata region:
//   0..3   magic ("KDF2" / "KDF3" / "KDF4")
//   4      KDF algorithm id
//   5      sentinel
//   6..7   random filler
//   8..23  Argon2id salt
//   24..47 secretstream header
//   48..51 Argon2id opslimit, big-endian   (V4 only; random filler before V4)
//   52..55 Argon2id memlimit, big-endian   (V4 only; random filler before V4)
pub(crate) const KDF_METADATA_MAGIC_V2: [u8; 4] = *b"KDF2";
pub(crate) const KDF_METADATA_MAGIC_V3: [u8; 4] = *b"KDF3";
pub(crate) const KDF_METADATA_MAGIC_V4: [u8; 4] = *b"KDF4";
pub(crate) const KDF_METADATA_REGION_BYTES: usize = 56;
pub(crate) const KDF_MAGIC_OFFSET: usize = 0;
pub(crate) const KDF_ALG_OFFSET: usize = 4;
pub(crate) const KDF_SENTINEL_OFFSET: usize = 5;
pub(crate) const KDF_SALT_OFFSET: usize = 8;
pub(crate) const KDF_NONCE_OFFSET: usize = 24;
pub(crate) const KDF_OPSLIMIT_OFFSET: usize = 48;
pub(crate) const KDF_MEMLIMIT_OFFSET: usize = 52;
pub(crate) const KDF_COST_FIELD_BYTES: usize = 4;
pub(crate) const KDF_ALG_ARGON2ID13: u8 = 1;
pub(crate) const KDF_SENTINEL: u8 = 0xA5;

/// Accepted range when reading Argon2id costs back out of an image. The floors
/// are libsodium's own minimums; the ceilings bound the work a hostile image
/// can demand, since Argon2id allocates memlimit bytes and runs opslimit passes
/// over them before the PIN is known to be wrong.
pub(crate) const KDF_OPSLIMIT_MAX_ACCEPTED: u64 = 16;
pub(crate) const KDF_MEMLIMIT_MAX_ACCEPTED: u64 = 512 * 1024 * 1024;

pub(crate) const STREAM_FRAME_LEN_BYTES: usize = 4;
pub(crate) const STREAM_MODE_ZLIB: u8 = 1;
pub(crate) const STREAM_MODE_RAW: u8 = 2;

pub(crate) const fn stream_mode_byte(is_compressed_payload: bool) -> u8 {
    if is_compressed_payload {
        STREAM_MODE_ZLIB
    } else {
        STREAM_MODE_RAW
    }
}
pub(crate) const STREAM_INFLATE_MAX_OUTPUT: usize = 3 * 1024 * 1024 * 1024;
pub(crate) const DATA_FILENAME_MAX_LENGTH: usize = 20;
pub(crate) const LARGE_FILE_SIZE: usize = 300 * 1024 * 1024;
pub(crate) const COMPRESS_BYPASS_SIZE: usize = 10 * 1024 * 1024;
pub(crate) const MAX_SIZE_CONCEAL: usize = 2 * 1024 * 1024 * 1024;
pub(crate) const SEGMENT_DATA_SIZE: usize = 65519;
pub(crate) const SEGMENT_HEADER_LENGTH: usize = 16;
pub(crate) const SOI_SIG_LENGTH: usize = 2;
pub(crate) const SEGMENT_SIG_LENGTH: usize = 2;
pub(crate) const PROFILE_DATA_SIZE: usize = 851;
pub(crate) const PROFILE_SIZE_DIFF: usize = 16;
pub(crate) const SEGMENT_HEADER_SIZE_INDEX: usize = 0x04;
pub(crate) const PROFILE_SIZE_INDEX: usize = 0x16;
pub(crate) const SEGMENTS_TOTAL_VAL_INDEX: usize = 0x2E0;
pub(crate) const DEFLATED_DATA_FILE_SIZE_INDEX: usize = 0x2E2;
pub(crate) const DEFAULT_DECRYPT_KDF_METADATA_INDEX: usize = 0x2FB;
pub(crate) const DEFAULT_KDF_METADATA_INDEX: usize = 0x313;
pub(crate) const DEFAULT_METADATA_PREFIX_BYTES: usize = 0x353;
pub(crate) const BASE_OFFSET_DEFAULT: usize = 24;
pub(crate) const DEFAULT_ICC_SIG_INDEX_ABS: usize = BASE_OFFSET_DEFAULT + 8;
pub(crate) const DEFAULT_JDVRIF_SIG_INDEX_ABS: usize = BASE_OFFSET_DEFAULT + 0x333;
pub(crate) const STREAM_CHUNK_SIZE: usize = 1024 * 1024;
pub(crate) const MAX_DATA_SIZE_BLUESKY: usize = 2 * 1024 * 1024;

// Indexes the conceal-mode platform *report* list built by
// platform_report_template() in conceal_helpers.rs (X-Twitter, Tumblr, Bluesky,
// Mastodon, Pixelfed, PostImage, ImgBB, ImgPile, Flickr) — NOT the
// PLATFORM_LIMITS table in conceal_helpers.rs, which omits Bluesky and is
// matched by name in finalize_default_platform_report. Keep in sync with the
// template's ordering.
pub(crate) const BLUESKY_PLATFORM_INDEX: usize = 2;

pub(crate) const BLUESKY_EXIF_SEGMENT_DATA_INSERT_INDEX: usize = 0x1D1;
pub(crate) const BLUESKY_COMPRESSED_FILE_SIZE_INDEX: usize = 0x1CD;
pub(crate) const BLUESKY_EXIF_SEGMENT_SIZE_INDEX: usize = 0x04;
pub(crate) const BLUESKY_ARTIST_FIELD_SIZE_INDEX: usize = 0x4A;
pub(crate) const BLUESKY_ARTIST_FIELD_SIZE_DIFF: usize = 140;
pub(crate) const BLUESKY_KDF_METADATA_INDEX: usize = 0x18D;

pub(crate) const DEFAULT_ICC_TEMPLATE: &[u8] = include_bytes!("templates/default_icc_template.bin");
pub(crate) const BLUESKY_EXIF_TEMPLATE: &[u8] =
    include_bytes!("templates/bluesky_exif_template.bin");
pub(crate) const PHOTOSHOP_SEGMENT_TEMPLATE: &[u8] =
    include_bytes!("templates/photoshop_segment_template.bin");
pub(crate) const XMP_SEGMENT_TEMPLATE: &[u8] = include_bytes!("templates/xmp_segment_template.bin");
