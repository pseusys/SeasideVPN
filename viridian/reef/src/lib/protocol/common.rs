use std::fmt;
use std::fmt::Display;
use std::ops::BitAnd;
use std::ops::BitOr;

use num_enum::IntoPrimitive;
use num_enum::TryFromPrimitive;


#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoPrimitive, TryFromPrimitive)]
pub enum ProtocolFlag {
    INIT = 128,
    HDSK = 64,
    DATA = 32,
    TERM = 16
}

impl BitOr for ProtocolFlag {
    type Output = u8;

    fn bitor(self, rhs: Self) -> Self::Output {
        (self as u8) | (rhs as u8)
    }
}

impl BitAnd for ProtocolFlag {
    type Output = u8;

    fn bitand(self, rhs: Self) -> Self::Output {
        (self as u8) & (rhs as u8)
    }
}

impl Display for ProtocolFlag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}


#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoPrimitive, TryFromPrimitive)]
pub enum ProtocolMessageType {
    Handshake      = ProtocolFlag::HDSK as u8,
    HandshakeData = (ProtocolFlag::HDSK as u8) | (ProtocolFlag::DATA as u8),
    Data           = ProtocolFlag::DATA as u8,
    Termination    = ProtocolFlag::TERM as u8
}

impl Display for ProtocolMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}


#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, IntoPrimitive, TryFromPrimitive)]
pub enum ProtocolReturnCode {
    Success = 0
}
