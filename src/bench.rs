#[macro_use] extern crate bencher;
use bencher::Bencher;

use bcp_rs::Bcp;

macro_rules! bitsize_bench {
    ($bench_name:ident, $bitsize:literal) => {
        fn $bench_name(bench: &mut Bencher) {
            bench.iter(|| {
                let _bcp = Bcp::new($bitsize);
            });
        }
    }
}

bitsize_bench!(a_bitsize_64, 64);
bitsize_bench!(b_bitsize_128, 128);
bitsize_bench!(c_bitsize_256, 256);
bitsize_bench!(d_bitsize_512, 512);

benchmark_group!(
    benches,
    a_bitsize_64,
    b_bitsize_128,
    c_bitsize_256,
    d_bitsize_512,
);
benchmark_main!(benches);
