// SPDX-License-Identifier: MIT
//! Compute reference inverses with the unchanged original native implementation.
use binius_field::{BinaryField128bGhash,Field};
use binius_field::WithUnderlier;
use std::io::{self,BufRead};
fn main(){
 for line in io::stdin().lock().lines(){
  let value=u128::from_str_radix(&line.expect("input line"),16).expect("u128 hex");
  let field=BinaryField128bGhash::new(value);
  let inverse=field.invert().unwrap_or(BinaryField128bGhash::ZERO);
  let product=field*inverse;
  println!("{:032x} {:032x} {:032x}",value,inverse.to_underlier(),product.to_underlier());
 }
}
