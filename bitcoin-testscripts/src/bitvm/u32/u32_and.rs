#![allow(dead_code)]

use crate::bitvm::u32::u32_zip::u32_copy_zip;
use bitcoin_utils::treepp::*;

/// The bitwise AND of two u8 elements.
/// Expects the u8_xor_table to be on the stack
pub fn u8_and(i: u32) -> Script {
    script! {
        // f_A = f(A)
        OP_DUP
        {i}
        OP_ADD
        OP_PICK

        // A_even = f_A << 1
        OP_DUP
        OP_DUP
        OP_ADD

        // A_odd = A - A_even
        OP_ROT
        OP_SWAP
        OP_SUB

        // f_B = f(B)
        OP_ROT
        OP_DUP
        {i + 1}
        OP_ADD
        OP_PICK

        // B_even = f_B << 1
        OP_DUP
        OP_DUP
        OP_ADD

        // B_odd = B - B_even
        OP_ROT
        OP_SWAP
        OP_SUB

        // A_andxor_B_even = f_A + f_B
        OP_SWAP
        3
        OP_ROLL
        OP_ADD
        // A_and_B_even = f(A_andxor_B_even)
        {i}
        OP_ADD
        OP_PICK

        // A_andxor_B_odd = A_odd + B_odd
        OP_SWAP
        OP_ROT
        OP_ADD

        // A_and_B_odd = f(A_andxor_B_odd)
        {i - 1}
        OP_ADD
        OP_PICK

        // A_and_B = A_and_B_odd + (A_and_B_even << 1)
        OP_OVER
        OP_ADD
        OP_ADD
    }
}

/// The bitwise AND of the u32 elements at address a and at address b. Drops a and b
///
/// Expects the u8_xor_table to be on the stack
pub fn u32_and(a: u32, b: u32, stack_size: u32) -> Script {
    assert_ne!(a, b);
    script! {
        {u32_copy_zip(a, b)}

        {u8_and(8 + (stack_size - 2) * 4)}

        OP_TOALTSTACK

        {u8_and(6 + (stack_size - 2) * 4)}

        OP_TOALTSTACK

        {u8_and(4 + (stack_size - 2) * 4)}

        OP_TOALTSTACK

        {u8_and(2 + (stack_size - 2) * 4)}

        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
    }
}

#[cfg(test)]
mod tests {

    use crate::bitvm::u32::u32_and::*;
    use crate::bitvm::u32::u32_std::*;
    use crate::bitvm::u32::u32_xor::{u8_drop_xor_table, u8_push_xor_table};
    use bitcoin_utils::debug::run_and_assert;
    use bitcoin_utils::treepp::script;
    use rand::Rng;

    fn and(x: u32, y: u32) -> u32 {
        x & y
    }

    #[test]
    fn test_and() {
        println!("u32 and: {} bytes", u32_and(0, 1, 3).len());
        for _ in 0..100 {
            let mut rng = rand::thread_rng();
            let x: u32 = rng.gen();
            let y: u32 = rng.gen();
            let exec_script = script! {
                {u8_push_xor_table()}
                {u32_push(x)}
                {u32_push(y)}
                {u32_and(0, 1, 3)}
                {u32_push(and(x, y))}
                {u32_equal()}
                OP_TOALTSTACK
                {u32_drop()} // drop y
                {u8_drop_xor_table()}
                OP_FROMALTSTACK
            };
            run_and_assert(exec_script);
        }
    }
}
