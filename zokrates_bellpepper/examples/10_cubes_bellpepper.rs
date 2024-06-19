use nova_snark::traits::{
    circuit::TrivialCircuit, snark::RelaxedR1CSSNARKTrait,
};
use nova_snark::RecursiveSNARK;
use pasta_curves::{Fp, Fq};
use std::io;
use std::time::Instant;
use typed_arena::Arena;
use zokrates_bellpepper::nova::{CompressedSNARK, NovaComputation};
use zokrates_bellpepper::Computation;
use zokrates_core::compile::{compile, CompileConfig};
use zokrates_field::PallasField;

// type G1 = pasta_curves::pallas::Point;
// type G2 = pasta_curves::vesta::Point;

use zokrates_bellpepper::nova::{PublicParams, F1, S1, S2};

fn main() {
    // create a circuit for the incremental computation

    let cube = r#"
        def main(field x) -> field {
            return x**3;
        }
    "#;

    let arena = Arena::new();

    let artifacts = compile::<PallasField, io::Error>(
        cube.to_string(),
        "main".into(),
        None,
        CompileConfig::default(),
        &arena,
    )
    .unwrap();

    let prog = artifacts.prog().collect();

    let circuit_primary =
        NovaComputation::try_from(Computation::without_witness(&prog))
            .unwrap();
    let circuit_secondary = TrivialCircuit::default();

    // produce public parameters
    println!("Producing public parameters...");
    let pp = PublicParams::setup(
        &circuit_primary,
        &circuit_secondary,
        &S1::ck_floor(),
        &S2::ck_floor(),
    )
    .unwrap();

    // produce a recursive SNARK
    println!("Generating a RecursiveSNARK...");

    let num_steps: usize = 10;

    let z0_primary = vec![Fq::one() + Fq::one()];
    let z0_secondary = vec![Fp::one()];

    let mut recursive_snark = RecursiveSNARK::new(
        &pp,
        &circuit_primary,
        &circuit_secondary,
        &z0_primary,
        &z0_secondary,
    )
    .unwrap();

    for i in 0..num_steps {
        let start = Instant::now();
        let res = recursive_snark.prove_step(
            &pp,
            &circuit_primary,
            &circuit_secondary,
        );
        assert!(res.is_ok());
        println!(
            "RecursiveSNARK::prove_step {}: {:?}, took {:?} ",
            i,
            res.is_ok(),
            start.elapsed()
        );
    }

    // verify the recursive SNARK
    println!("Verifying a RecursiveSNARK...");
    let start = Instant::now();
    let res =
        recursive_snark.verify(&pp, num_steps, &z0_primary, &z0_secondary);

    println!("{:#?}", res);

    println!(
        "RecursiveSNARK::verify: {:?}, took {:?}",
        res.is_ok(),
        start.elapsed()
    );
    assert!(res.is_ok());

    // produce a compressed SNARK
    println!("Generating a CompressedSNARK using Spartan with IPA-PC...");
    let start = Instant::now();
    // type EE1 = nova_snark::provider::ipa_pc::EvaluationEngine<G1>;
    // type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<G2>;
    // type S1 = nova_snark::spartan::RelaxedR1CSSNARK<G1, EE1>;
    // type S2 = nova_snark::spartan::RelaxedR1CSSNARK<G2, EE2>;

    let (pk, vk) = CompressedSNARK::setup(&pp).unwrap();

    let res = CompressedSNARK::prove(&pp, &pk, &recursive_snark);
    println!(
        "CompressedSNARK::prove: {:?}, took {:?}",
        res.is_ok(),
        start.elapsed()
    );
    assert!(res.is_ok());
    let compressed_snark = res.unwrap();

    // verify the compressed SNARK
    println!("Verifying a CompressedSNARK...");
    let start = Instant::now();
    let res =
        compressed_snark.verify(&vk, num_steps, &z0_primary, &z0_secondary);
    println!(
        "CompressedSNARK::verify: {:?}, took {:?}",
        res.is_ok(),
        start.elapsed()
    );
    assert!(res.is_ok());
    println!("=========================================================");
}
