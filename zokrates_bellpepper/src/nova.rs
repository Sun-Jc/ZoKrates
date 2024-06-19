use std::collections::BTreeMap;

use crate::Computation;
use bellpepper_core::num::AllocatedNum;
use bellpepper_core::ConstraintSystem;
use bellpepper_core::SynthesisError;
// use bellperson::gadgets::num::AllocatedNum;
// use bellperson::SynthesisError;
use ff::Field as FFField;
use nova_snark::errors::NovaError;
use nova_snark::traits::circuit::StepCircuit;
use nova_snark::traits::circuit::TrivialCircuit;
use nova_snark::traits::snark::RelaxedR1CSSNARKTrait;
// use nova_snark::traits::snark::RelaxedR1CSSNARKTrait;
// use nova_snark::traits::snark::RelaxedR1CSSNARKTrait;
use nova_snark::traits::Group;
// use nova_snark::CompressedSNARK as GCompressedSNARK;
// pub use nova_snark::PublicParams as GPublicParams;
// pub use nova_snark::RecursiveSNARK as GRecursiveSNARK;
use nova_snark::VerifierKey as GVerifierKey;
use serde::{Deserialize, Serialize};
use std::fmt;
use zokrates_ast::ir::*;
use zokrates_field::{BellpepperFieldExtensions, Cycle, Field};
use zokrates_interpreter::Interpreter;

pub trait NovaField:
    Field
    + BellpepperFieldExtensions<
        BellpepperField = <<Self as Cycle>::Point as Group>::Scalar,
    > + Cycle
{
}

// type T = zokrates_field::PallasField;
// pub type E1 = nova_snark::provider::PallasEngine;
// type E2 = nova_snark::provider::VestaEngine;
// pub type F1 = <E1 as nova_snark::traits::Engine>::Scalar;
// // pub type E2 = nova_snark::provider::VestaEngine;
// pub type C1<'ast> = NovaComputation<'ast>;
// // pub type C2 = TrivialCircuit<<<T as Cycle>::Point as Group>::Base>;
// pub type EE1 = nova_snark::provider::ipa_pc::EvaluationEngine<E1>;

// pub type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>;

// TODO: The other way around?
type T = zokrates_field::GrumpkinField;
pub type E1 = nova_snark::provider::hyperkzg::Bn256EngineKZG;
pub type E2 = nova_snark::provider::GrumpkinEngine;
pub type F1 = <E1 as nova_snark::traits::Engine>::Scalar;
type EE1 = nova_snark::provider::hyperkzg::EvaluationEngine<E1>;
pub type S1 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E1, EE1>;

pub type C1<'ast> = NovaComputation<'ast>;

// pub type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<E2>;
// pub type S2 = nova_snark::spartan::snark::RelaxedR1CSSNARK<E2, EE2>;

// use nova_snark::{
//     cyclefold::{
//         CompressedSNARK as CompressedSNARKCF, ProverKey as ProverKeyCF,
//         PublicParams as PublicParamsCF, RecursiveSNARK as RecursiveSNARKCF,
//         VerifierKey as VerifierKeyCF,
//     },
//     traits::{
//         circuit::StepCircuit, snark::BatchedRelaxedR1CSSNARKTrait, Engine,
//     },
// };

pub type GPublicParams<'ast> =
    nova_snark::cyclefold::PublicParams<E1, E2, C1<'ast>>;
pub type GRecursiveSNARK<'ast> =
    nova_snark::cyclefold::RecursiveSNARK<E1, E2, C1<'ast>>;

impl<
        T: Field
            + BellpepperFieldExtensions<
                BellpepperField = <<Self as Cycle>::Point as Group>::Scalar,
            > + Cycle,
    > NovaField for T
{
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NovaComputation<'ast> {
    #[serde(skip_serializing, skip_deserializing)]
    step_private: Option<Vec<T>>,
    #[serde(skip_serializing, skip_deserializing)]
    computation: Computation<'ast, T>,
}

impl<'ast> Default for NovaComputation<'ast> {
    fn default() -> Self {
        todo!()
    }
}
impl<'ast, T> Default for Computation<'ast, T> {
    fn default() -> Self {
        todo!()
    }
}

impl<'ast> TryFrom<Computation<'ast, T>> for NovaComputation<'ast> {
    type Error = Error;
    fn try_from(c: Computation<'ast, T>) -> Result<Self, Self::Error> {
        let return_count = c.program.return_count;
        let public_input_count = c.program.public_count() - return_count;

        if public_input_count != return_count {
            return Err(Error::User(format!("Number of return values must match number of public input values for Nova circuits, found `{} != {}`", c.program.return_count, public_input_count)));
        }

        Ok(NovaComputation {
            step_private: None,
            computation: c,
        })
    }
}

// type E1<T> = nova_snark::traits::Engine<Scalar = T>;

// type G1<T> = <T as Cycle>::Point;
// type G2<T> = <<T as Cycle>::Other as Cycle>::Point;
// type C1<'ast, T> = NovaComputation<'ast, T>;
// type C2<T> = TrivialCircuit<<<T as Cycle>::Point as Group>::Base>;

// type PublicParams<'ast, T> = GPublicParams<G1<T>, G2<T>, C1<'ast, T>, C2<T>>;
// pub type RecursiveSNARK<'ast, T> = GRecursiveSNARK<G1<T>, G2<T>, C1<'ast, T>, C2<T>>;

#[derive(Debug)]
pub enum Error {
    Internal(NovaError),
    User(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Internal(e) => write!(f, "Internal error: {:#?}", e),
            Error::User(s) => write!(f, "{}", s),
        }
    }
}

impl From<NovaError> for Error {
    fn from(e: NovaError) -> Self {
        Self::Internal(e)
    }
}

pub fn generate_public_parameters<
    'ast,
    // T: Field
    //     + BellpepperFieldExtensions<BellpepperField = <<T as Cycle>::Point as Group>::Scalar>
    //     + Cycle,
>(
    program: &'ast Prog<'ast, T>,
) -> Result<GPublicParams<'ast>, Error> {
    Ok(GPublicParams::setup(
        &NovaComputation::try_from(Computation::without_witness(program))?,
        &*S1::ck_floor(),
    ))
}

pub fn verify<'ast>(
    params: &GPublicParams<'ast>,
    proof: &RecursiveSNARKWithStepCount,
    arguments: Vec<T>,
) -> Result<Vec<T>, Error> {
    let z0_primary: Vec<_> =
        arguments.into_iter().map(|a| a.into_bellpepper()).collect();
    // let z0_secondary = vec![<<T as Cycle>::Point as Group>::Base::ONE];

    proof
        .proof
        .verify(params, proof.steps, &z0_primary)
        .map_err(Error::Internal)
        .map(|primary| primary.into_iter().map(T::from_bellpepper).collect())
}

#[derive(Serialize, Debug, Deserialize)]
pub struct RecursiveSNARKWithStepCount<'ast> {
    // #[serde(bound = "T: NovaField")]
    pub proof: GRecursiveSNARK<'ast>,
    pub steps: usize,
}

// type EE1<T> = nova_snark::provider::ipa_pc::EvaluationEngine<G1<T>>;
// type EE2<T> = nova_snark::provider::ipa_pc::EvaluationEngine<G2<T>>;
// type S1<T> = nova_snark::spartan::RelaxedR1CSSNARK<G1<T>, EE1<T>>;
// type S2<T> = nova_snark::spartan::RelaxedR1CSSNARK<G2<T>, EE2<T>>;

pub type CompressedSNARK<'ast> =
    nova_snark::cyclefold::CompressedSNARK<E1, E2, C1<'ast>, S1>;
pub type VerifierKey<'ast> =
    nova_snark::cyclefold::VerifierKey<E1, E2, C1<'ast>, S1>;

pub fn compress<'ast>(
    public_parameters: &GPublicParams<'ast>,
    instance: RecursiveSNARKWithStepCount<'ast>,
) -> (CompressedSNARK<'ast>, VerifierKey<'ast>) {
    let (pk, vk) = CompressedSNARK::<'ast>::setup(public_parameters).unwrap();

    (
        CompressedSNARK::prove(public_parameters, &pk, &instance.proof)
            .unwrap(),
        vk,
    )
}

pub fn verify_compressed<'ast>(
    proof: &CompressedSNARK<'ast>,
    vk: &VerifierKey<'ast>,
    arguments: Vec<T>,
    step_count: usize,
) -> bool {
    let z0_primary: Vec<_> =
        arguments.into_iter().map(|a| a.into_bellpepper()).collect();
    // let z0_secondary = vec![<<T as Cycle>::Point as Group>::Base::ONE];

    // proof
    //     .verify(vk, step_count, &z0_primary, zn)
    //     .is_ok()
    // TODO
    true
}

pub fn prove<'ast>(
    public_parameters: &GPublicParams<'ast>,
    program: &'ast Prog<'ast, T>,
    arguments: Vec<T>,
    mut proof: Option<RecursiveSNARKWithStepCount<'ast>>,
    steps: impl IntoIterator<Item = Vec<T>>,
) -> Result<Option<RecursiveSNARKWithStepCount<'ast>>, Error> {
    let c_primary =
        NovaComputation::try_from(Computation::without_witness(program))?;
    // let c_secondary = TrivialCircuit::default();
    let z0_primary: Vec<_> =
        arguments.into_iter().map(|a| a.into_bellpepper()).collect();
    // let z0_secondary: Vec<_> = vec![<<T as Cycle>::Point as Group>::Base::ONE];

    let steps = steps.into_iter().collect::<Vec<_>>();
    let mut c_primary = c_primary.clone();
    c_primary.step_private = Some(steps[0].clone());

    let (mut recursive_snark, mut n_steps) = if let Some(proof) = proof {
        (proof.proof, proof.steps)
    } else {
        (
            GRecursiveSNARK::<'ast>::new(
                public_parameters,
                &c_primary,
                &z0_primary,
            )
            .map_err(Error::Internal)?,
            0,
        )
    };

    for steps_private in steps[1..].iter() {
        let mut c_primary = c_primary.clone();
        c_primary.step_private = Some(steps_private.clone());

        n_steps += 1;

        recursive_snark
            .prove_step(&public_parameters, &c_primary)
            .unwrap();
    }

    proof = Some(RecursiveSNARKWithStepCount {
        proof: recursive_snark.clone(),
        steps: n_steps,
    });

    Ok(proof)
}

impl<'ast> StepCircuit<F1> for NovaComputation<'ast> {
    fn arity(&self) -> usize {
        let output_count = self.computation.program.return_count;
        let input_count =
            self.computation.program.public_count() - output_count;
        assert_eq!(input_count, output_count);
        input_count
    }

    fn synthesize<CS: ConstraintSystem<F1>>(
        &self,
        cs: &mut CS,
        input: &[AllocatedNum<F1>],
    ) -> Result<Vec<AllocatedNum<F1>>, SynthesisError> {
        let output_count = self.computation.program.return_count;
        let input_count =
            self.computation.program.public_count() - output_count;
        assert_eq!(input_count, output_count);

        let mut symbols = BTreeMap::new();

        let mut witness = Witness::default();

        let outputs = self.computation.program.returns();

        // populate the witness if we got some input values
        // this is a bit hacky and in particular generates the witness in all cases if there are no inputs
        if input
            .first()
            .map(|n| n.get_value().is_some())
            .unwrap_or(true)
        {
            let interpreter = Interpreter::default();
            let inputs: Vec<_> = input
                .iter()
                .map(|v| T::from_bellpepper(v.get_value().unwrap()))
                .chain(self.step_private.clone().into_iter().flatten())
                .collect();

            let program = self.computation.program;

            witness = interpreter
                .execute(
                    &inputs,
                    program.statements.iter(),
                    &program.arguments,
                    &program.solvers,
                )
                .unwrap();
        }

        // allocate the inputs
        for (p, allocated_num) in
            self.computation.program.arguments.iter().zip(input)
        {
            symbols.insert(p.id, allocated_num.get_variable());
        }

        // allocate the outputs

        let outputs: Vec<_> = outputs
            .iter()
            .map(|v| {
                assert!(v.id < 0); // this should indeed be an output
                let wire = AllocatedNum::alloc(
                    cs.namespace(|| {
                        format!("NOVA_INCREMENTAL_OUTPUT_{}", -v.id - 1)
                    }),
                    || {
                        Ok(witness
                            .0
                            .remove(v)
                            .ok_or(SynthesisError::AssignmentMissing)?
                            .into_bellpepper())
                    },
                )
                .unwrap();
                symbols.insert(*v, wire.get_variable());
                wire
            })
            .collect();

        self.computation.synthesize_input_to_output(
            cs,
            &mut symbols,
            &mut witness,
        )?;

        Ok(outputs)
    }

    // fn output(&self, z: &[T::BellpepperField]) -> Vec<T::BellpepperField> {
    //     let interpreter = Interpreter::default();
    //     let inputs: Vec<_> = z
    //         .iter()
    //         .map(|v| T::from_bellpepper(*v))
    //         .chain(self.step_private.clone().unwrap())
    //         .collect();

    //     let program = self.computation.program;
    //     let output = interpreter
    //         .execute(
    //             &inputs,
    //             program.statements.iter(),
    //             &program.arguments,
    //             &program.solvers,
    //         )
    //         .unwrap();

    //     output
    //         .return_values()
    //         .into_iter()
    //         .map(|v| v.into_bellpepper())
    //         .collect()
    // }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use zokrates_ast::ir::LinComb;

//     mod prove {
//         use super::*;
//         use zokrates_ast::flat::Parameter;
//         use zokrates_ast::ir::Prog;
//         use zokrates_field::PallasField;

//         fn test<T: NovaField>(
//             program: Prog<T>,
//             initial_state: Vec<T>,
//             step_privates: Vec<Vec<T>>,
//             expected_final_state: Vec<T>,
//         ) {
//             let params = generate_public_parameters(&program).unwrap();
//             let proof = prove(
//                 &params,
//                 &program,
//                 initial_state.clone(),
//                 None,
//                 step_privates,
//             )
//             .unwrap()
//             .unwrap();
//             assert_eq!(
//                 verify(&params, &proof, initial_state).unwrap(),
//                 expected_final_state
//             );
//         }

//         #[test]
//         fn empty() {
//             let program: Prog<PallasField> = Prog::default();
//             test(program, vec![], vec![vec![]; 3], vec![]);
//         }

//         #[test]
//         fn identity() {
//             let program: Prog<PallasField> = Prog {
//                 arguments: vec![Parameter::public(Variable::new(0))],
//                 return_count: 1,
//                 statements: vec![Statement::constraint(
//                     Variable::new(0),
//                     Variable::public(0),
//                     None,
//                 )],
//                 module_map: Default::default(),
//                 solvers: vec![],
//             };

//             test(
//                 program,
//                 vec![PallasField::from(0)],
//                 vec![vec![]; 3],
//                 vec![PallasField::from(0)],
//             );
//         }

//         #[test]
//         fn plus_one() {
//             let program = Prog {
//                 arguments: vec![Parameter::public(Variable::new(42))],
//                 return_count: 1,
//                 statements: vec![Statement::constraint(
//                     LinComb::from(Variable::new(42)) + LinComb::one(),
//                     Variable::public(0),
//                     None,
//                 )],
//                 module_map: Default::default(),
//                 solvers: vec![],
//             };

//             test(
//                 program,
//                 vec![PallasField::from(3)],
//                 vec![vec![]; 3],
//                 vec![PallasField::from(6)],
//             );
//         }

//         #[test]
//         fn private_gaps() {
//             let program = Prog {
//                 arguments: vec![
//                     Parameter::public(Variable::new(42)),
//                     Parameter::public(Variable::new(51)),
//                 ],
//                 return_count: 2,
//                 statements: vec![
//                     Statement::constraint(
//                         LinComb::from(Variable::new(42)) + LinComb::from(Variable::new(51)),
//                         Variable::public(0),
//                         None,
//                     ),
//                     Statement::constraint(
//                         LinComb::from(Variable::new(51)) + LinComb::from(Variable::new(42)),
//                         Variable::public(1),
//                         None,
//                     ),
//                 ],
//                 module_map: Default::default(),
//                 solvers: vec![],
//             };

//             test(
//                 program,
//                 vec![PallasField::from(0), PallasField::from(1)],
//                 vec![vec![]; 3],
//                 vec![PallasField::from(4), PallasField::from(4)],
//             );
//         }

//         #[test]
//         fn fold() {
//             // def main(public field acc, field e) -> field {
//             //     return acc + e
//             // }

//             // called with init 2 and round private inputs [1, 2, 3]
//             // should return (((2 + 1) + 2) + 3) = 8

//             let program = Prog {
//                 arguments: vec![
//                     Parameter::public(Variable::new(0)),
//                     Parameter::private(Variable::new(1)),
//                 ],
//                 return_count: 1,
//                 statements: vec![Statement::constraint(
//                     LinComb::from(Variable::new(0)) + LinComb::from(Variable::new(1)),
//                     Variable::public(0),
//                     None,
//                 )],
//                 module_map: Default::default(),
//                 solvers: vec![],
//             };

//             test(
//                 program,
//                 vec![PallasField::from(2)],
//                 vec![
//                     vec![PallasField::from(1)],
//                     vec![PallasField::from(2)],
//                     vec![PallasField::from(3)],
//                 ],
//                 vec![PallasField::from(8)],
//             );
//         }

//         #[test]
//         fn complex_fold() {
//             // def main(public field[2] acc, field[2] e) -> field[2] {
//             //     return [acc[0] + e[0], acc[1] + e[1]]
//             // }

//             // called with init [2, 3] and round private inputs [[1, 2], [3, 4], [5, 6]]
//             // should return [2 + 1 + 3 + 5, 3 + 2 + 4 + 6] = [11, 15]

//             let program = Prog {
//                 arguments: vec![
//                     Parameter::public(Variable::new(0)),
//                     Parameter::public(Variable::new(1)),
//                     Parameter::private(Variable::new(2)),
//                     Parameter::private(Variable::new(3)),
//                 ],
//                 return_count: 2,
//                 statements: vec![
//                     Statement::constraint(
//                         LinComb::from(Variable::new(0)) + LinComb::from(Variable::new(2)),
//                         Variable::public(0),
//                         None,
//                     ),
//                     Statement::constraint(
//                         LinComb::from(Variable::new(1)) + LinComb::from(Variable::new(3)),
//                         Variable::public(1),
//                         None,
//                     ),
//                 ],
//                 module_map: Default::default(),
//                 solvers: vec![],
//             };

//             test(
//                 program,
//                 vec![PallasField::from(2), PallasField::from(3)],
//                 vec![
//                     vec![PallasField::from(1), PallasField::from(2)],
//                     vec![PallasField::from(3), PallasField::from(4)],
//                     vec![PallasField::from(5), PallasField::from(6)],
//                 ],
//                 vec![PallasField::from(11), PallasField::from(15)],
//             );
//         }
//     }
// }
