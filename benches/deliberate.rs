use std::collections::BTreeMap;
use std::hint::black_box;
use std::time::Instant;
use tokala::Council;

fn main() {
    let council = Council::new();
    let mut args = BTreeMap::new();
    args.insert("command".to_string(), "rm -rf /tmp/cache".to_string());

    let n = 100_000;
    let t = Instant::now();
    for _ in 0..n {
        black_box(council.deliberate(black_box("run_shell"), black_box(&args)));
    }
    let e = t.elapsed();
    println!(
        "deliberate (14 seats + encode): {n} ops in {:?} ({:.0} ns/op)",
        e,
        e.as_nanos() as f64 / n as f64
    );
}
