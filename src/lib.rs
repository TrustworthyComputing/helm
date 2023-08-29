pub mod ascii;
pub mod circuit;
pub mod gates;
pub mod verilog_parser;

use std::fmt;
use std::{collections::HashMap, fmt::Debug, str::FromStr};
use termion::color;
use tfhe::prelude::*;
use tfhe::{FheUint16, FheUint32};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PtxtError {
    #[error("Invalid input")]
    InvalidInput,
}

#[derive(Clone, Debug)]
pub enum PtxtType {
    Uint32(u32),
    Uint16(u16),
    None,
}

#[derive(Clone)]
pub enum FheType {
    Uint32(FheUint32),
    Uint16(FheUint16),
    None,
}

impl FromStr for PtxtType {
    type Err = PtxtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "None" {
            Ok(PtxtType::None)
        } else if let Ok(value) = u32::from_str(s) {
            Ok(PtxtType::Uint32(value))
        } else if let Ok(value) = u16::from_str(s) {
            Ok(PtxtType::Uint16(value))
        } else {
            Err(PtxtError::InvalidInput)
        }
    }
}

impl fmt::Display for PtxtType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PtxtType::Uint32(value) => write!(f, "Uint32({})", value),
            PtxtType::Uint16(value) => write!(f, "Uint16({})", value),
            PtxtType::None => write!(f, "None"),
        }
    }
}

impl FheType {
    fn decrypt(&self, client_key: &tfhe::ClientKey) -> PtxtType {
        match self {
            FheType::Uint32(inner_value) => PtxtType::Uint32(inner_value.decrypt(client_key)),
            FheType::Uint16(inner_value) => PtxtType::Uint16(inner_value.decrypt(client_key)),
            FheType::None => panic!("Decrypt found a None value"),
        }
    }
}

pub fn get_input_wire_map<T>(wire_file: Option<String>) -> HashMap<String, T>
where
    T: FromStr,
    T::Err: Debug,
{
    if let Some(wire_file_name) = &wire_file {
        return verilog_parser::read_input_wires::<T>(wire_file_name);
    }

    println!(
        "{}[!]{} No CSV file provided for the input wires, they will be initialized to false.",
        color::Fg(color::LightYellow),
        color::Fg(color::Reset)
    );

    HashMap::new()
}
