#![allow(non_snake_case)]
#![feature(test)]

extern crate md5;
extern crate test;

#[bench] fn compute_____1_000(bencher: &mut test::Bencher) { compute(    1_000, bencher); }
#[bench] fn compute____10_000(bencher: &mut test::Bencher) { compute(   10_000, bencher); }
#[bench] fn compute___100_000(bencher: &mut test::Bencher) { compute(  100_000, bencher); }
#[bench] fn compute_1_000_000(bencher: &mut test::Bencher) { compute(1_000_000, bencher); }

fn compute(size: usize, bencher: &mut test::Bencher) {
    let data = &vec![0xFFu8; size][..];
    bencher.iter(|| {
        test::black_box(md5::compute(data));
    });
}
