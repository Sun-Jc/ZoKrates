pub mod nova;

// use bellperson::gadgets::num::AllocatedNum;
// use bellperson::{
//     Circuit, ConstraintSystem, LinearCombination, SynthesisError, Variable as BellpersonVariable,
// };

use bellpepper_core::num::AllocatedNum;
use bellpepper_core::{
    Circuit, ConstraintSystem, LinearCombination, SynthesisError, Variable as BellpepperVariable,
};
use std::collections::BTreeMap;
use zokrates_ast::common::flat::Variable;
use zokrates_ast::ir::{LinComb, Prog, Statement, Witness};
use zokrates_field::BellpepperFieldExtensions;
use zokrates_field::Field;

pub struct Bellpepper;

#[derive(Clone, Debug)]
pub struct Computation<'ast, T> {
    pub program: &'ast Prog<'ast, T>,
    pub witness: Option<Witness<T>>,
}

impl<'ast, T: Field> Computation<'ast, T> {
    pub fn with_witness(program: &'ast Prog<'ast, T>, witness: Witness<T>) -> Self {
        Computation {
            program,
            witness: Some(witness),
        }
    }

    pub fn without_witness(program: &'ast Prog<'ast, T>) -> Self {
        Computation {
            program,
            witness: None,
        }
    }
}

fn bellpepper_combination<
    T: Field + BellpepperFieldExtensions,
    CS: ConstraintSystem<T::BellpepperField>,
>(
    l: &LinComb<T>,
    cs: &mut CS,
    symbols: &mut BTreeMap<Variable, BellpepperVariable>,
    witness: &mut Witness<T>,
) -> LinearCombination<T::BellpepperField> {
    l.value
        .iter()
        .map(|(k, v)| {
            (
                v.into_bellpepper(),
                *symbols.entry(*k).or_insert_with(|| {
                    match k.is_output() {
                        true => {
                            unreachable!("outputs should already have been allocated, found {}", k)
                        }
                        false => AllocatedNum::alloc(cs.namespace(|| format!("{}", k)), || {
                            Ok(witness
                                .0
                                .remove(k)
                                .ok_or(SynthesisError::AssignmentMissing)?
                                .into_bellpepper())
                        }),
                    }
                    .unwrap()
                    .get_variable()
                }),
            )
        })
        .fold(LinearCombination::zero(), |acc, e| acc + e)
}

impl<'ast, T: BellpepperFieldExtensions + Field> Circuit<T::BellpepperField>
    for Computation<'ast, T>
{
    fn synthesize<CS: ConstraintSystem<T::BellpepperField>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let mut symbols = BTreeMap::new();

        let mut witness = self.witness.clone().unwrap_or_else(Witness::empty);

        assert!(symbols.insert(Variable::one(), CS::one()).is_none());

        symbols.extend(self.program.arguments.iter().enumerate().map(|(index, p)| {
            let wire = match p.private {
                true => {
                    AllocatedNum::alloc(cs.namespace(|| format!("PRIVATE_INPUT_{}", index)), || {
                        Ok(witness
                            .0
                            .remove(&p.id)
                            .ok_or(SynthesisError::AssignmentMissing)?
                            .into_bellpepper())
                    })
                }
                false => AllocatedNum::alloc_input(
                    cs.namespace(|| format!("PUBLIC_INPUT_{}", index)),
                    || {
                        Ok(witness
                            .0
                            .remove(&p.id)
                            .ok_or(SynthesisError::AssignmentMissing)?
                            .into_bellpepper())
                    },
                ),
            }
            .unwrap();
            (p.id, wire.get_variable())
        }));

        self.program.returns().iter().for_each(|v| {
            assert!(v.id < 0); // this should indeed be an output
            let wire = AllocatedNum::alloc_input(
                cs.namespace(|| format!("PUBLIC_OUTPUT_{}", -v.id - 1)),
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
        });

        self.synthesize_input_to_output(cs, &mut symbols, &mut witness)
    }
}

impl<'ast, T: BellpepperFieldExtensions + Field> Computation<'ast, T> {
    pub fn synthesize_input_to_output<CS: ConstraintSystem<T::BellpepperField>>(
        &self,
        cs: &mut CS,
        symbols: &mut BTreeMap<Variable, BellpepperVariable>,
        witness: &mut Witness<T>,
    ) -> Result<(), SynthesisError> {
        for (i, statement) in self.program.statements.iter().enumerate() {
            if let Statement::Constraint(constraint) = statement {
                let a = &bellpepper_combination(&constraint.quad.left, cs, symbols, witness);
                let b = &bellpepper_combination(&constraint.quad.right, cs, symbols, witness);
                let c = &bellpepper_combination(&constraint.lin, cs, symbols, witness);

                cs.enforce(
                    || format!("Constraint {}", i),
                    |lc| lc + a,
                    |lc| lc + b,
                    |lc| lc + c,
                );
            }
        }

        Ok(())
    }

    pub fn public_inputs_values(&self) -> Vec<T::BellpepperField> {
        self.program
            .public_inputs_values(self.witness.as_ref().unwrap())
            .iter()
            .map(|v| v.into_bellpepper())
            .collect()
    }
}
