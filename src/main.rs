use std::{env, time::Duration};

use ark_bls12_381::{Fr, G1Affine, G1Projective as G1};
use ark_ec::{CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_ff::{UniformRand, Zero};

use std::hint::black_box as bb;
use criterion::Criterion;

use rand::thread_rng;

fn parse_args() -> (usize, usize) {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        panic!("Usage: ibe_schemes <NUM_MSMS> <MSM_SIZE>")
    }
    let num_msms = args[1].parse::<usize>().unwrap();
    let msm_size = args[2].parse::<usize>().unwrap();
    (num_msms, msm_size)
}

fn compute_msms(num_msms: usize, msm_size: usize, bases: &Vec<G1Affine>, scalars: &Vec<Fr>) -> G1 {
    let mut res = G1::zero();
    for i in 0..num_msms {
        let offset = i*msm_size;
        let bs = &bases[offset..offset+msm_size];
        let ss = &scalars[offset..offset+msm_size];
        let tmp: G1 = VariableBaseMSM::msm(bs, ss).unwrap();
        res += tmp;
    }
    res
}

fn main() {
    let mut rng = thread_rng();
    let (num_msms, msm_size) = parse_args();

    let total = num_msms * msm_size;

    let scalars: Vec<Fr> = (0..total).map(|_| Fr::rand(&mut rng)).collect();
    let bases: Vec<G1Affine> = (0..total)
        .map(|_| Fr::rand(&mut rng))
        .map(|e| G1::generator() * e)
        .map(|g| g.into_affine())
        .collect();

    let desc = format!("{} x {}-msm", num_msms, msm_size);
    let mut c = Criterion::default().measurement_time(Duration::new(10, 0));
    c.bench_function(&desc, |b| {
        b.iter(|| compute_msms(bb(num_msms), bb(msm_size), bb(&bases), bb(&scalars)));
    });

    println!("Finished");
}
