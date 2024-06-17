use ark_vesta::Fr as VestaBaseField;
#[cfg(feature = "bellperson_extensions")]
use pasta_curves::Fp;

#[cfg(feature = "bellperson_extensions")]
use crate::{Cycle, PallasField};

use crate::G2Type;

#[cfg(feature = "bellperson_extensions")]
impl Cycle for FieldPrime {
    type Other = PallasField;
    type Point = pasta_curves::vesta::Point;
}

#[cfg(feature = "bellpepper_extensions")]
use pasta_curves::Fp;

#[cfg(feature = "bellpepper_extensions")]
use crate::{Cycle, PallasField};

#[cfg(feature = "bellpepper_extensions")]
impl Cycle for FieldPrime {
    type Other = PallasField;
    type Point = pasta_curves::vesta::Point;
}
#[cfg(feature = "bellpepper_extensions")]
bellpepper_extensions!(Fp);

prime_field!("vesta", VestaBaseField, G2Type::Fq2);

#[cfg(feature = "bellperson_extensions")]
bellperson_extensions!(Fp);
