#![allow(non_snake_case)]
#![allow(dead_code)]

use crate::treepp::*;

pub fn OP_CHECKSEQUENCEVERIFY() -> Script {
    script! { OP_CSV }
}

/// OP_4PICK
/// The 4 items n back in the stack are copied to the top.
pub fn OP_4PICK() -> Script {
    script! {
        OP_ADD
        OP_DUP  OP_PICK OP_SWAP
        OP_DUP  OP_PICK OP_SWAP
        OP_DUP  OP_PICK OP_SWAP
        OP_1SUB OP_PICK
    }
}

/// OP_4ROLL
/// The 4 items n back in the stack are moved to the top.
pub fn OP_4ROLL() -> Script {
    script! {
        4 OP_ADD
        OP_DUP  OP_ROLL OP_SWAP
        OP_DUP  OP_ROLL OP_SWAP
        OP_DUP  OP_ROLL OP_SWAP
        OP_1SUB OP_ROLL
    }
}

/// Duplicates the top 4 items
pub fn OP_4DUP() -> Script {
    script! {
        OP_2OVER OP_2OVER
    }
}

/// Drops the top 4 items
pub fn OP_4DROP() -> Script {
    script! {
        OP_2DROP OP_2DROP
    }
}

/// Swaps the top two groups of 4 items
pub fn OP_4SWAP() -> Script {
    script! {
        7 OP_ROLL 7 OP_ROLL
        7 OP_ROLL 7 OP_ROLL
    }
}

/// Puts the top 4 items onto the top of the alt stack. Removes them from the main stack.
pub fn OP_4TOALTSTACK() -> Script {
    script! {
        OP_TOALTSTACK OP_TOALTSTACK OP_TOALTSTACK OP_TOALTSTACK
    }
}

/// Puts the top 4 items from the altstack onto the top of the main stack. Removes them from the alt stack.
pub fn OP_4FROMALTSTACK() -> Script {
    script! {
        OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
    }
}

//
// Multiplication by Powers of 2
//

/// The top stack item is multiplied by 2
pub fn OP_2MUL() -> Script {
    script! {
        OP_DUP OP_ADD
    }
}

/// The top stack item is multiplied by 4
pub fn OP_4MUL() -> Script {
    script! {
        OP_DUP OP_ADD OP_DUP OP_ADD
    }
}

/// The top stack item is multiplied by 2**k
pub fn OP_2K_MUL(k: usize) -> Script {
    script! {
        for _ in 0..k {
            { OP_2MUL() }
        }
    }
}

/// The top stack item is multiplied by 16
pub fn OP_16MUL() -> Script {
    script! {
        OP_DUP OP_ADD OP_DUP OP_ADD
        OP_DUP OP_ADD OP_DUP OP_ADD
    }
}

/// The top stack item is multiplied by 256
pub fn OP_256MUL() -> Script {
    script! {
        OP_DUP OP_ADD OP_DUP OP_ADD
        OP_DUP OP_ADD OP_DUP OP_ADD
        OP_DUP OP_ADD OP_DUP OP_ADD
        OP_DUP OP_ADD OP_DUP OP_ADD
    }
}

/// Pushes the element, consisting of `length` limbs
/// back to the mainstack from the altstack
pub fn OP_LONGFROMALTSTACK(length: usize) -> Script {
    script! {
        for _ in 0..length {
            OP_FROMALTSTACK
        }
    }
}

pub fn OP_NDUP(n: usize) -> Script {
    let times_3_dup = if n > 3 { (n - 3) / 3 } else { 0 };
    let remaining = if n > 3 { (n - 3) % 3 } else { 0 };

    script! {

        if n >= 1 {
            OP_DUP
        }


        if n >= 3 {
            OP_2DUP
        }
        else if n >= 2{
            OP_DUP
        }


        for _ in 0..times_3_dup {
            OP_3DUP
        }

        if remaining == 2{
            OP_2DUP
        }
        else if remaining == 1{
            OP_DUP
        }

    }
}

pub fn push_to_stack(element: usize, n: usize) -> Script {
    script! {
        if n >= 1{
                {element} {OP_NDUP(n - 1)}
        }
    }
}

pub fn NMUL(n: u32) -> Script {
    let n_bits = u32::BITS - n.leading_zeros();
    let bits = (0..n_bits).map(|i| 1 & (n >> i)).collect::<Vec<_>>();
    script! {
        if n_bits == 0 { OP_DROP 0 }
        else {
            for i in 0..bits.len()-1 {
                if bits[i] == 1 { OP_DUP }
                { crate::pseudo::OP_2MUL() }
            }
            for _ in 1..bits.iter().sum() { OP_ADD }
        }
    }
}
