# jdvrif-rs
***This is an experimental Rust port of my C++ steganography tool [***jdvrif***](https://github.com/CleasbyCode/jdvrif)***

***jdvrif-rs*** is a fast, easy-to-use steganography command-line tool for concealing and extracting any file type via a **JPG** image.  

There is also a [***Web edition***](https://cleasbycode.co.uk/jdvrif/app/), which you can use immediately, as a convenient alternative to downloading and compiling the CLI source code. Web file uploads are limited to **20MB**.    

![Demo Image](https://github.com/CleasbyCode/jdvrif-rs/blob/main/demo_image/jrif_661748.jpg)  
*Demo Image: **"A place of concealment"** / ***PIN: 5608171548286279209****

Unlike the common steganography method of concealing data within the pixels of a cover image ([***LSB***](https://ctf101.org/forensics/what-is-stegonagraphy/)), ***jdvrif-rs*** hides files within ***application segments*** of a ***JPG*** image. 

You can conceal any file type up to ***2GB***, although compatible sites (*listed below*) have their own ***much smaller*** size limits and *other requirements.  

For increased storage capacity and better security, your embedded data file is compressed with ***flate2/zlib*** — unless it's already a compressed file type over 10 MB — and encrypted with ***XChaCha20-Poly1305*** using the ***libsodium*** cryptographic library (via the Rust ***alkali*** bindings).

***jdvrif-rs*** partly derives from the ***[technique implemented](https://www.vice.com/en/article/bj4wxm/tiny-picture-twitter-complete-works-of-shakespeare-steganography)*** by security researcher ***[David Buchanan](https://www.da.vidbuchanan.co.uk/).*** 

## Compilation & Usage (Linux)

```console
$ sudo apt install libsodium-dev libturbojpeg0-dev pkg-config 
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
$ cargo build --release

$ sudo cp target/release/jdvrif-rs /usr/bin 
$ jdvrif-rs 

Usage: jdvrif-rs conceal [-b|-r] <cover_image> <secret_file>
       jdvrif-rs recover <cover_image>  
       jdvrif-rs --info

$ jdvrif-rs conceal your_cover_image.jpg your_secret_file.doc

Platform compatibility for output image:-

  ✓ X-Twitter
  ✓ Tumblr
  ✓ Mastodon
  ✓ Pixelfed
  ✓ PostImage
  ✓ ImgBB
  ✓ ImgPile
  ✓ Flickr
  
Saved "file-embedded" JPG image: jrif_3e1988793.jpg (143029 bytes).

Recovery PIN: [***2166776980318349924***]

Important: Keep your PIN safe, so that you can extract the hidden file.

Complete!
        
$ jdvrif-rs recover jrif_3e1988793.jpg

PIN: *******************

Extracted hidden file: your_secret_file.doc (6165 bytes).

Complete! Please check your file.

```
jdvrif-rs ***mode*** arguments:
 
 ***conceal*** - Compresses, encrypts and embeds your secret data file within a ***JPG*** cover image.  
 ***recover*** - Decrypts, uncompresses and extracts the concealed data file from a ***JPG*** cover image.
 
jdvrif-rs ***conceal*** mode ***platform*** options:
 
"***-b***" To create compatible "*file-embedded*" ***JPG*** images for posting on the ***Bluesky*** platform, you must use the ***-b*** option with ***conceal*** mode.
  ```console
  $ jdvrif-rs conceal -b my_image.jpg hidden.doc
  ```
\******************   
Note: ***Bluesky*** now saves images as ***WEBP*** by default. 

To save an image as ***JPG***, so that you can still recover concealed data with ***jdvrif-rs***,  
right-click on an image that you want to save. From the menu, select ***Open image in new tab***.  

Select the new tab and within the address bar, move to the end of the address and add ***@jpg*** then hit enter.  
Right-click the image and from the menu select ***Save image...***  

Your image should now be downloaded as a ***JPG***, which will now work with ***jdvrif-rs***.
         
If you want a tool to conceal data using ***WEBP*** images to post on ***Bluesky*** you can use my ***WEBP*** steganography CLI tool ***[wbpdv](https://github.com/CleasbyCode/wbpdv)***  
\******************

 These images are only compatible for posting on ***Bluesky***. Your embedded data file will be removed if posted on a different platform.
 
  You are also required to use the Python script ***"bsky_post.py"*** (found in the repo ***src*** folder) to post the image to ***Bluesky***.
  It will not work if you post images to ***Bluesky*** via the browser site or mobile app.  

  To use the script, you will need to create an [***app password***](https://bsky.app/settings/app-passwords) from your ***Bluesky*** account.  

  Here are some basic usage examples for the ***bsky_post.py*** script.  

  Standard image post to your bsky profile:


  ```console
  $ python3 bsky_post.py --handle you.bsky.social --password xxxx-xxxx-xxxx-xxxx --image your_image.jpg --alt-text "alt-text here (optional)" "standard post text here (required)"
  ```
  If you want to post multiple images (Max. 4):  

  ```console 
  $ python3 bsky_post.py --handle you.bsky.social --password xxxx-xxxx-xxxx-xxxx --image img1.jpg --image img2.jpg --alt-text "alt_here" "standard post text..."
  ```
  If you want to post an image as a reply to another thread:  

  ```console
  $ python3 bsky_post.py --handle you.bsky.social --password xxxx-xxxx-xxxx-xxxx --image your_image.jpg --alt-text "alt_here" --reply-to https://bsky.app/profile/someone.bsky.social/post/8m2tgw6cgi23i "standard post text..."
  ```

https://github.com/user-attachments/assets/c8c38e6d-ea23-4d67-98d9-cebdcd82b449

https://github.com/user-attachments/assets/b2cc33ff-b2c2-46c2-960b-f7b9ba65223d

## Compatible Platforms
*Posting size limit measured by the ***combined*** size of the ***cover image*** + ***compressed data file:****  

● ***Flickr*** (**200MB**), ***ImgPile*** (**100MB**), ***ImgBB*** (**32MB**),  
● ***PostImage*** (**32MB**), ***Reddit*** (**20MB** | ***-r option***), ***Pixelfed*** (**15MB**).

*Size limit measured ***only*** by the ***compressed data file size:****  

● ***Mastodon*** (**~6MB**), ***Tumblr*** (**~64KB**), ***X-Twitter*** (**~10KB**).  

For example, with ***Mastodon***, if your cover image is **1MB** you can still embed a data file up to the **~6MB** size limit.

**Other: The ***Bluesky*** platform has ***separate*** size limits for the ***cover image*** and the ***compressed data file:****  

● ***Bluesky*** (***-b option***). Cover image size limit (**800KB**). Compressed data file size limit (**~171KB**).  
● "***bsky_post.py***" script is required to post images on ***Bluesky***. *More info on this further down the page.*

For platforms such as ***X-Twitter*** & ***Tumblr***, which have small size limits, you may want to focus on data that compress well, such as text files, etc.   

https://github.com/user-attachments/assets/b4c72ea7-40e3-49b0-89aa-ae2dd8ccccb9 

   "***-r***" - To create compatible "*file-embedded*" ***JPG*** images for posting on the ***Reddit*** platform, you must use the ***-r*** option with ***conceal*** mode.
   ```console
  $ jdvrif-rs conceal -r my_image.jpg secret.mp3 
   ```
   From the ***Reddit*** site, select "***Create Post***" followed by "***Images & Video***" tab, to attach and post your ***JPG*** image.
  
   These images are only compatible for posting on ***Reddit***. Your embedded data file will be removed if posted on a different platform.
  
 To correctly download images from ***X-Twitter*** or ***Reddit***, click the image in the post to fully expand it, before saving.

https://github.com/user-attachments/assets/f56f54bb-658f-4b0e-a2f3-7d3428333304

## Third-Party Software

  ***jdvrif-rs*** uses the following third-party software:

  ### Native libraries

  - [libsodium](https://github.com/jedisct1/libsodium) — cryptographic operations.
    License: [ISC](https://github.com/jedisct1/libsodium/blob/master/LICENSE).

  - [libjpeg-turbo](https://github.com/libjpeg-turbo/libjpeg-turbo) (TurboJPEG API) — JPEG
  processing and lossless transformation.
    Licenses: [Independent JPEG Group License and Modified BSD 3-Clause License](https://github.com/
    libjpeg-turbo/libjpeg-turbo/blob/main/LICENSE.md).

    This software is based in part on the work of the Independent JPEG Group.

  ### Rust dependencies

  - [alkali](https://github.com/tom25519/alkali) — safe Rust bindings to libsodium.
    License: MIT OR Apache-2.0.
    Uses [libsodium-sys-stable](https://github.com/jedisct1/libsodium-sys-stable), licensed under
    MIT OR Apache-2.0.

  - [flate2](https://github.com/rust-lang/flate2-rs) — DEFLATE/zlib-stream compression and
  decompression.
    License: MIT OR Apache-2.0.
    Uses the pure-Rust [miniz_oxide](https://github.com/Frommi/miniz_oxide) backend, licensed under
    MIT OR zlib OR Apache-2.0.

  - [libc](https://github.com/rust-lang/libc) — Linux/POSIX and C FFI bindings.
    License: MIT OR Apache-2.0.

  - [zeroize](https://github.com/RustCrypto/utils/tree/master/zeroize) — clearing sensitive values
  from memory.
    License: MIT OR Apache-2.0.

  ### Incorporated assets

  - [Compact ICC Profiles](https://github.com/saucecontrol/Compact-ICC-Profiles) — modified
  `AdobeCompat-v4.icc` profile embedded in the default JPEG metadata template.
    License: CC0 1.0.

  ### Optional Bluesky posting helper

  The optional `bsky_post.py` helper uses:

  - [Requests](https://github.com/psf/requests) — Apache License 2.0.
  - [Beautiful Soup 4](https://pypi.org/project/beautifulsoup4/) — MIT License.
  - [Pillow](https://github.com/python-pillow/Pillow) — MIT-CMU License.
    
##

