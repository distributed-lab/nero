use crate::treepp::*;

/// Checks whether two elements, consisting of multiple limbs, are equal.
///
/// - **Input:** `{ a[0], a[1], ..., a[l-1], b[0], b[1], ..., b[l-1] }`
/// - **Returns:** A single bit equal `a[0]==b[0] && a[1]==b[1] && ... && a[l-1]==b[l-1]`
///
/// If `length = 0`, we assume that two elements are equal
#[allow(non_snake_case)]
pub fn OP_LONGEQUAL(length: usize) -> Script {
    if length == 0 {
        return script! { OP_TRUE };
    }

    script! {
        for j in (0..length).rev() {
            { j+1 } OP_ROLL OP_EQUAL OP_TOALTSTACK
        }

        OP_FROMALTSTACK
        for _ in 0..length - 1 {
            OP_FROMALTSTACK
            OP_BOOLAND
        }
    }
}

/// Asserts that two elements, consisting of multiple limbs, are equal.
///
/// - **Input:** `{ a[0], a[1], ..., a[l-1], b[0], b[1], ..., b[l-1] }`
/// - **Returns:** Panics if the condition
///   `{ a[0] == b[0] && a[1] == b[1] && ... && a[l-1] == b[l-1] }` does not hold.
///
/// In case `length = 0`, we assume that two elements are equal and therefore do nothing.
#[allow(non_snake_case)]
pub fn OP_LONGEQUALVERIFY(length: usize) -> Script {
    if length == 0 {
        return script! {};
    }

    script! {
        for j in (0..length).rev() {
            { j+1 } OP_ROLL OP_EQUALVERIFY
        }
    }
}

/// Checks whether two elements, consisting of multiple limbs, are not equal.
///
/// - **Input:** `{ a[0], a[1], ..., a[l-1], b[0], b[1], ..., b[l-1] }`
/// - **Returns:** `{ a[0] != b[0] || a[1] != b[1] || ... || a[l-1] != b[l-1] }`
///
/// If `length = 0`, we assume two elements to be equal and thus we return the `0` bit.
#[allow(non_snake_case)]
pub fn OP_LONGNOTEQUAL(length: usize) -> Script {
    if length == 0 {
        return script! { OP_FALSE };
    }

    script! {
        // Writing bits a[i] != b[i] for each i in the altstack
        for j in (0..length).rev() {
            { j+1 } OP_ROLL OP_EQUAL OP_NOT OP_TOALTSTACK
        }

        // Verifying that at least one of the bits is true
        OP_FROMALTSTACK
        for _ in 0..length - 1 {
            OP_FROMALTSTACK
            OP_BOOLOR
        }
    }
}

/// Asserts that two elements, consisting of multiple limbs, are not equal.
///
/// - **Input:** `{ a[0], a[1], ..., a[l-1], b[0], b[1], ..., b[l-1] }`
/// - **Returns:** `{ a[0] != b[0] || a[1] != b[1] || ... || a[l-1] != b[l-1] }`
///
/// If `length = 0`, we assume two elements are not equal and thus panic.
#[allow(non_snake_case)]
pub fn OP_LONGNOTEQUALVERIFY(length: usize) -> Script {
    script! {
        { OP_LONGNOTEQUAL(length) }
        { 1 } OP_EQUALVERIFY
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(non_snake_case)]
    fn test_OP_LONGEQUAL_true() {
        let script = script! {
            1 2 3 4 5 1 2 3 4 5
            { OP_LONGEQUAL(5) }
        };

        let exec_result = execute_script(script);
        assert!(exec_result.success, "OP_LONGEQUAL(5) failed");
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_OP_LONGEQUAL_false() {
        let script = script! {
            1 2 3 4 5 1 2 3 4 6
            { OP_LONGEQUAL(5) }
            OP_FALSE OP_EQUAL
        };

        let exec_result = execute_script(script);
        assert!(exec_result.success, "OP_LONGEQUAL(5) failed");
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_OP_LONGEQUALVERIFY() {
        let script = script! {
            1 2 3 4 5 1 2 3 4 5
            { OP_LONGEQUALVERIFY(5) }
            OP_TRUE
        };

        let exec_result = execute_script(script);
        assert!(exec_result.success, "OP_LONGEQUALVERIFY(5) failed");
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_OP_LONGNOTEQUALVERIFY_happy_flow() {
        let script = script! {
            1 2 3 4 5 1 2 4 4 5
            { OP_LONGNOTEQUAL(5) }
            { 1 } OP_EQUAL
        };

        let exec_result = execute_script(script);
        assert!(exec_result.success, "OP_LONGNOTEQUALVERIFY(5) failed");
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_OP_LONGNOTEQUALVERIFY_should_fail() {
        let script = script! {
            1 2 3 4 5 1 2 3 4 5
            { OP_LONGNOTEQUAL(5) }
            { 0 } OP_EQUAL
        };

        let exec_result = execute_script(script);
        assert!(exec_result.success, "OP_LONGNOTEQUALVERIFY(5) failed");
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_OP_LONGNOTEQUAL_short_1() {
        let script = script! {
            1 2
            { OP_LONGNOTEQUAL(1) }
            { 1 } OP_EQUAL
        };

        let exec_result = execute_script(script);
        assert!(exec_result.success, "OP_LONGNOTEQUAL(1) failed");
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_OP_LONGNOTEQUAL_short_2() {
        let script = script! {
            3 3
            { OP_LONGNOTEQUAL(1) }
            { 0 } OP_EQUAL
        };

        let exec_result = execute_script(script);
        assert!(exec_result.success, "OP_LONGNOTEQUAL(1) failed");
    }
}
