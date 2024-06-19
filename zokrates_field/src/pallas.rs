use ark_pallas::Fr as PallasBaseField;

#[cfg(feature = "bellpepper_extensions")]
use crate::{Cycle, VestaField};
#[cfg(feature = "bellpepper_extensions")]
use pasta_curves::Fq;

use crate::G2Type;

#[cfg(feature = "bellpepper_extensions")]
impl Cycle for FieldPrime {
    type Other = VestaField;
    type Point = pasta_curves::pallas::Point;
}

#[cfg(feature = "bellpepper_extensions")]
bellpepper_extensions!(Fq);

prime_field!("pallas", PallasBaseField, G2Type::Fq2);
