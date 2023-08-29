pub mod ascii;
pub mod circuit;
pub mod gates;
pub mod verilog_parser;

use std::fmt;
use std::{collections::HashMap, fmt::Debug, str::FromStr};
use termion::color;
use tfhe::prelude::*;
use tfhe::{FheUint128, FheUint16, FheUint32, FheUint64, FheUint8};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PtxtError {
    #[error("Invalid input")]
    InvalidInput,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PtxtType {
    Bool(bool),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    None,
}

#[derive(Clone)]
pub enum FheType {
    U8(FheUint8),
    U16(FheUint16),
    U32(FheUint32),
    U64(FheUint64),
    U128(FheUint128),
    None,
}

impl FromStr for PtxtType {
    type Err = PtxtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "None" {
            Ok(PtxtType::None)
        } else if let Ok(value) = u8::from_str(s) {
            Ok(PtxtType::U8(value))
        } else if let Ok(value) = u16::from_str(s) {
            Ok(PtxtType::U16(value))
        } else if let Ok(value) = u32::from_str(s) {
            Ok(PtxtType::U32(value))
        } else if let Ok(value) = u64::from_str(s) {
            Ok(PtxtType::U64(value))
        } else if let Ok(value) = u128::from_str(s) {
            Ok(PtxtType::U128(value))
        } else {
            Err(PtxtError::InvalidInput)
        }
    }
}

impl fmt::Display for PtxtType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PtxtType::Bool(value) => write!(f, "Bool({})", value),
            PtxtType::U8(value) => write!(f, "U8({})", value),
            PtxtType::U16(value) => write!(f, "U16({})", value),
            PtxtType::U32(value) => write!(f, "U32({})", value),
            PtxtType::U64(value) => write!(f, "U64({})", value),
            PtxtType::U128(value) => write!(f, "U128({})", value),
            PtxtType::None => write!(f, "None"),
        }
    }
}

impl FheType {
    fn decrypt(&self, client_key: &tfhe::ClientKey) -> PtxtType {
        match self {
            FheType::U8(inner_value) => PtxtType::U8(inner_value.decrypt(client_key)),
            FheType::U16(inner_value) => PtxtType::U16(inner_value.decrypt(client_key)),
            FheType::U32(inner_value) => PtxtType::U32(inner_value.decrypt(client_key)),
            FheType::U64(inner_value) => PtxtType::U64(inner_value.decrypt(client_key)),
            FheType::U128(inner_value) => PtxtType::U128(inner_value.decrypt(client_key)),
            FheType::None => panic!("Decrypt found a None value"),
        }
    }
}

pub fn get_input_wire_map(wire_file: Option<String>, ptxt_type: &str) -> HashMap<String, PtxtType> {
    if let Some(wire_file_name) = &wire_file {
        return verilog_parser::read_input_wires(wire_file_name, ptxt_type);
    }

    println!(
        "{}[!]{} No CSV file provided for the input wires, they will be initialized to false.",
        color::Fg(color::LightYellow),
        color::Fg(color::Reset)
    );

    HashMap::new()
}
