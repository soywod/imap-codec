#![no_main]
use libfuzzer_sys::fuzz_target;

use imap_codec::{codec::Encoder, parse::response::response};

fuzz_target!(|data: &[u8]| {
    if let Ok((rem, parsed1)) = response(data) {
        let input = &data[..data.len() - rem.len()];

        //println!("libFuzzer:  {}", String::from_utf8_lossy(input).trim());
        //println!("parsed:     {:?}", parsed1);

        let input = parsed1.encode();
        //println!("serialized: {}", String::from_utf8_lossy(&input).trim());
        let (rem, parsed2) = response(&input).unwrap();
        //println!("parsed:     {:?}", parsed2);
        assert!(rem.is_empty());

        assert_eq!(parsed1, parsed2);

        //println!("\n\n\n");
    }
});
