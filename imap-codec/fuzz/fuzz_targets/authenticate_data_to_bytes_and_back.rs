#![no_main]

use imap_codec::auth::AuthenticateData;
use imap_codec_fuzz::impl_to_bytes_and_back;

impl_to_bytes_and_back!(AuthenticateData);