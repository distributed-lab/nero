//! This module contains the [`IntermediateState`] struct, which is used to store the intermediate
//! state of the stack and altstack during the execution of a script split into the shards (subprograms).

use core::fmt;

use bitcoin_scriptexec::Stack;
use bitcoin_utils::{stack_to_script, treepp::*};

/// Structure that represents the intermediate state.
/// It contains the stack and altstack after the execution of the
/// corresponding shard.
#[derive(Clone)]
pub struct IntermediateState {
    pub stack: Stack,
    pub altstack: Stack,
}

/// Structure that represents the [`IntermediateState`] where stack and altstack are
/// serialized to bytes.
pub struct IntermediateStateAsBytes {
    pub stack: Vec<u8>,
    pub altstack: Vec<u8>,
}

impl fmt::Debug for IntermediateState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Stack: {:?}", self.stack)?;
        writeln!(f, "Altstack: {:?}", self.altstack)
    }
}

impl IntermediateState {
    /// Returns the script that pushes all elements (stack and altstack) to the
    /// corresponding stacks
    pub fn inject_script(&self) -> Script {
        script! {
            // Checks for length of the stack and altstack
            // are used to avoid panic when referencing the first element
            // of the stack or altstack (by using get(0) method)
            if !self.stack.is_empty() {
                { stack_to_script(&self.stack) }
            }

            if !self.altstack.is_empty() {
                { stack_to_script(&self.altstack) }

                for i in (0..self.altstack.len()).rev() {
                    { i } OP_ROLL
                    OP_TOALTSTACK
                }
            }
        }
    }

    /// Creates a new instance of the IntermediateState based on the given
    /// script and the stack and altstack after the execution of the script
    pub fn from_inject_script(inject_script: &Script) -> Self {
        let result = execute_script(inject_script.clone());

        Self {
            stack: result.main_stack.clone(),
            altstack: result.alt_stack.clone(),
        }
    }

    /// Executes the script with the given input and returns the intermediate result,
    /// that is, the stack and altstack after the execution
    pub fn from_input_script(input: &Script, script: &Script) -> Self {
        let script = script! {
            { input.clone() }
            { script.clone() }
        };

        let result = execute_script(script);

        Self {
            stack: result.main_stack.clone(),
            altstack: result.alt_stack.clone(),
        }
    }

    /// Based on the previous intermediate result, executes the script with the stacks
    /// and altstacks of the previous result and returns the new intermediate result
    pub fn from_intermediate_result(result: &Self, script: &Script) -> Self {
        Self::from_input_script(&result.inject_script(), script)
    }

    /// Converts the stack to bytes
    pub fn to_bytes(&self) -> IntermediateStateAsBytes {
        IntermediateStateAsBytes {
            stack: self.stack.clone().serialize_to_bytes(),
            altstack: self.altstack.clone().serialize_to_bytes(),
        }
    }

    /// Returns the size of the stack and altstack
    pub fn size(&self) -> usize {
        self.stack.len() + self.altstack.len()
    }

    /// Converts the stack to a vector of u32 values
    pub fn interpret_as_u32_array(&self) -> Vec<u8> {
        self.stack.clone().serialize_to_bytes()
    }
}

impl IntermediateStateAsBytes {
    /// Represents the stack as a vector of u32 values.
    pub fn stack_as_u32(&self) -> Vec<u32> {
        bytes_to_u32_array(&self.stack)
    }

    /// Represents the altstack as a vector of u32 values.
    pub fn altstack_as_u32(&self) -> Vec<u32> {
        bytes_to_u32_array(&self.altstack)
    }

    /// Injects the stack and altstack into the script
    pub fn inject_script(&self) -> Script {
        script! {
            // Inject the stack
            for stack_element in self.stack_as_u32() {
                { stack_element }
            }

            // Inject the altstack
            for altstack_element in self.altstack_as_u32() {
                { altstack_element }
            }
            for i in (0..self.altstack_as_u32().len()).rev() {
                { i } OP_ROLL
                OP_TOALTSTACK
            }
        }
    }
}

/// Converts a slice of bytes to a vector of u32 values.
pub(super) fn bytes_to_u32_array(bytes: &[u8]) -> Vec<u32> {
    let mut u32_array = Vec::with_capacity(usize::div_ceil(bytes.len(), 4)); // Ceiling division to account for partial chunks.

    for chunk in bytes.chunks(4) {
        // Handle chunks with fewer than 4 bytes
        let padded_chunk = match chunk.len() {
            4 => [chunk[0], chunk[1], chunk[2], chunk[3]],
            3 => [chunk[0], chunk[1], chunk[2], 0],
            2 => [chunk[0], chunk[1], 0, 0],
            1 => [chunk[0], 0, 0, 0],
            _ => unreachable!(),
        };

        // Convert the padded chunk to a u32 value
        let value = u32::from_le_bytes(padded_chunk);
        u32_array.push(value);
    }

    u32_array
}
