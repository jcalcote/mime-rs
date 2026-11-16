//! Test-only allocator instrumentation; production code forbids unsafe code.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use crate::{Classification, Detector, MAX_RULE_TEXT_BYTES};

#[derive(Clone, Copy, Debug, Default)]
struct Stats {
    bytes: usize,
    count: usize,
    requests: usize,
    peak_bytes: usize,
    peak_count: usize,
}

thread_local! { static ACTIVE: Cell<Option<Stats>> = const { Cell::new(None) }; }

fn allocate(size: usize) {
    let _ = ACTIVE.try_with(|cell| {
        if let Some(mut stats) = cell.get() {
            stats.bytes += size;
            stats.count += 1;
            stats.requests += 1;
            stats.peak_bytes = stats.peak_bytes.max(stats.bytes);
            stats.peak_count = stats.peak_count.max(stats.count);
            cell.set(Some(stats));
        }
    });
}

fn deallocate(size: usize) {
    let _ = ACTIVE.try_with(|cell| {
        if let Some(mut stats) = cell.get() {
            stats.bytes -= size;
            stats.count -= 1;
            cell.set(Some(stats));
        }
    });
}

struct Allocator;
// SAFETY: Every operation forwards its original pointer/layout to System. The
// recorder uses only const-initialized thread-local cells and allocates nothing.
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        allocate(layout.size());
        // SAFETY: Identical GlobalAlloc contract forwarded to System.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        allocate(layout.size());
        // SAFETY: Identical GlobalAlloc contract forwarded to System.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        deallocate(layout.size());
        // SAFETY: Original allocator pointer/layout are forwarded unchanged.
        unsafe { System.dealloc(pointer, layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        // Count full old/new overlap, even when System can grow in place.
        allocate(size);
        deallocate(layout.size());
        // SAFETY: Original pointer/layout and requested size are forwarded.
        unsafe { System.realloc(pointer, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

fn measure<T>(operation: impl FnOnce() -> T) -> (T, Stats) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            ACTIVE.with(|cell| cell.set(None));
        }
    }
    ACTIVE.with(|cell| {
        assert!(cell.get().is_none());
        cell.set(Some(Stats::default()));
    });
    let reset = Reset;
    let result = operation();
    let stats = ACTIVE.with(|cell| cell.get().unwrap());
    drop(reset);
    (result, stats)
}

#[test]
fn construction_and_repeated_detection_allocate_nothing() {
    let detector = Detector::with_rules(
        "0 belong&0xfffffff0 0x12345670 custom\n!:mime application/x-custom\n",
    )
    .unwrap();
    let (_, stats) = measure(|| {
        let builtin = Detector::new();
        for _ in 0..1024 {
            assert!(matches!(
                builtin.detect(b"\x1f\x8b"),
                Classification::Match(_)
            ));
            assert!(matches!(
                builtin.detect_segments(&[b"RI", b"FF....", b"WEBP"]),
                Classification::Match(_)
            ));
            assert!(matches!(
                detector.detect(&[0x12, 0x34, 0x56, 0x78]),
                Classification::Match(_)
            ));
            assert_eq!(builtin.detect(b"prose"), Classification::Unknown);
            assert_eq!(builtin.detect(b""), Classification::Empty);
            assert!(builtin.match_bounds().mime_bytes > 0);
        }
    });
    assert_eq!(stats.requests, 0);
}

#[test]
fn compiler_peak_bounds_and_retained_inventory_cover_adversarial_sources() {
    let plan = Detector::compile_plan().unwrap();
    let mut groups = String::new();
    for _ in 0..256 {
        groups.push_str(&format!(
            "0 string A {}\n!:mime application/x-{}\n",
            "n".repeat(100),
            "m".repeat(100)
        ));
    }
    let mut checks = String::from("0 string A same\n");
    checks.push_str(&format!(">0 string {} same\n", "A".repeat(40)).repeat(1023));
    let mut failed = groups.clone();
    failed.push_str("0 regex A unsupported\n");
    let blank = " ".repeat(MAX_RULE_TEXT_BYTES);
    for text in [&groups, &checks, &failed, &blank] {
        let (result, stats) = measure(|| Detector::with_rules(text));
        assert!(stats.peak_bytes <= plan.peak_bytes, "{stats:?} vs {plan:?}");
        assert!(
            stats.peak_count <= plan.peak_allocations,
            "{stats:?} vs {plan:?}"
        );
        if let Ok(detector) = result {
            let (bytes, count) = detector
                .retained_allocations()
                .fold((0, 0), |(b, n), l| (b + l.size(), n + 1));
            assert_eq!((stats.bytes, stats.count), (bytes, count));
        } else {
            assert_eq!((stats.bytes, stats.count), (0, 0));
        }
    }
}

#[test]
fn copying_has_exact_requests_and_mismatch_is_allocation_free() {
    let detector = Detector::new();
    let classification = detector.detect(b"%PDF-");
    let plan = classification.copy_plan().unwrap();
    let (result, stats) = measure(|| plan.copy(classification));
    let owned = result.unwrap();
    assert_eq!(stats.bytes, plan.retained_bytes());
    assert_eq!(stats.count, plan.allocation_layouts().count());
    assert_eq!(
        owned
            .retained_allocations()
            .map(|l| l.size())
            .sum::<usize>(),
        stats.bytes
    );
    let (result, stats) = measure(|| plan.copy(Classification::Unknown));
    assert_eq!(result, Err(crate::CopyError::PlanMismatch));
    assert_eq!(stats.requests, 0);
    let (result, stats) = measure(|| {
        Classification::Empty
            .copy_plan()
            .unwrap()
            .copy(Classification::Empty)
    });
    assert_eq!(result.unwrap().retained_allocations().count(), 0);
    assert_eq!(stats.requests, 0);
}
