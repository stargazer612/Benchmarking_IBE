// use ibe_schemes::*;
use std::time::Instant;

fn main() {
    println!("\nTesting Affine MAC"); 
    let af_time = Instant::now();
    // test_affine_mac();
    let af_duration = af_time.elapsed();
    println!("Affine Mac Runtime: {:.2?}", af_duration);
    
    println!("\n\nTesting IBKEM1");
    let ibkem1_time = Instant::now();
    // test_ibkem1();
    let ib1_duration = ibkem1_time.elapsed();
    println!("IBKEM1 Runtime: {:.2?}", ib1_duration);
    
    
    println!("\n\nTesting QANIZK");
    let q_time = Instant::now();
    // test_qanizk();
    let q_duration = q_time.elapsed();
    println!("QANIZK Runtime: {:.2?}", q_duration);

    println!("\n\nTesting IBKEM2");
    let ib2_time = Instant::now();
    // test_ibkem2();    
    let ib2_duration = ib2_time.elapsed();
    println!("IBKEM2 Runtime: {:.2?}", ib2_duration);

    println!("\n\nTesting IBKEM2 correctness");
    // correctness_ibkem2();
}
