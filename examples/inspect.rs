use mime_inspect::{Classification, Detector};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let detector = Detector::with_rules(
        "0 string DEMO demonstration\n!:mime application/x-demo\n!:compression unspecified\n",
    )?;
    for bytes in [
        b"%PDF-1.7".as_slice(),
        b"DEMO content",
        b"unrecognized content",
        b"",
    ] {
        match detector.detect(bytes) {
            Classification::Empty => println!("empty prefix"),
            Classification::Unknown => println!("unknown signature"),
            Classification::Match(found) => println!(
                "{:?}: {:?}, hint {:?}",
                found.origin, found.mime, found.compression_hint
            ),
        }
    }
    Ok(())
}
