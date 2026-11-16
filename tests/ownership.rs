use mime_inspect::{
    Classification, CompressionHint, CopyError, Detector, Match, MatchBounds, Origin,
};

#[test]
fn owned_copy_outlives_detector_and_input() {
    let owned = {
        let detector =
            Detector::with_rules("0 string DEMO example\n!:mime application/x-example\n").unwrap();
        let input = b"DEMO".to_vec();
        let result = detector.detect(&input);
        let plan = result.copy_plan().unwrap();
        assert_eq!(
            plan.retained_bytes(),
            "application/x-example".len() + "example".len()
        );
        let owned = plan.copy(result).unwrap();
        assert_eq!(
            owned.retained_allocations().collect::<Vec<_>>(),
            plan.allocation_layouts().collect::<Vec<_>>()
        );
        owned
    };
    assert_eq!(
        owned.as_borrowed(),
        Classification::Match(Match {
            mime: Some("application/x-example"),
            name: Some("example"),
            origin: Origin::Custom,
            compression_hint: CompressionHint::Unspecified,
        })
    );
}

#[test]
fn empty_unknown_and_empty_strings_need_no_allocation_request() {
    for result in [
        Classification::Empty,
        Classification::Unknown,
        Classification::Match(Match {
            mime: Some(""),
            name: None,
            origin: Origin::Custom,
            compression_hint: CompressionHint::Unspecified,
        }),
    ] {
        let plan = result.copy_plan().unwrap();
        assert_eq!(plan.retained_bytes(), 0);
        assert_eq!(plan.allocation_layouts().count(), 0);
        let owned = plan.copy(result).unwrap();
        assert_eq!(owned.retained_allocations().count(), 0);
        assert_eq!(owned.as_borrowed(), result);
    }
    assert_eq!(
        Classification::Empty
            .copy_plan()
            .unwrap()
            .copy(Classification::Unknown),
        Err(CopyError::PlanMismatch)
    );
    let bound = MatchBounds {
        mime_bytes: usize::MAX,
        name_bytes: 0,
    };
    assert_eq!(bound.retained_bytes(), Err(CopyError::SizeOverflow));
    assert!(bound.allocation_layouts().is_err());
}

#[test]
fn custom_maxima_are_available_before_input_and_each_copy_checks_its_shape() {
    let name = "n".repeat(300);
    let mime = format!("application/x-{}", "m".repeat(200));
    let detector = Detector::with_rules(&format!("0 string A {name}\n!:mime {mime}\n")).unwrap();
    let bounds = detector.match_bounds();
    assert_eq!(bounds.name_bytes, name.len());
    assert_eq!(bounds.mime_bytes, mime.len());
    let result = detector.detect(b"A");
    let plan = result.copy_plan().unwrap();
    assert!(plan.retained_bytes() <= bounds.retained_bytes().unwrap());
    assert_eq!(
        plan.copy(detector.detect(b"unknown")),
        Err(CopyError::PlanMismatch)
    );
    assert_eq!(Detector::new().retained_allocations().count(), 0);
}
