#![cfg_attr(not(test), no_std)]

pub mod codes;

mod poll_reply;
pub use poll_reply::*;

use byte::{BytesExt, BE, LE};
use core::ops::{Deref, RangeInclusive};

use nom::{
    bytes::complete::tag,
    number::complete as number,
    number::complete::{be_u16, le_u16},
    sequence::tuple,
    IResult,
};

const ID: &'static [u8] = b"Art-Net\0";
pub const PORT: u16 = 0x1936;

const DEFAULT_4_BYTES: &'static [u8; 4] = &[0; 4];
const DEFAULT_6_BYTES: &'static [u8; 6] = &[0; 6];

const PROTOCOL_VERSION: u16 = 14;

#[derive(Debug)]
pub enum Art<'a> {
    Poll(Poll),
    PollReply(PollReply<'a>),
    Command(Command<'a>),
    Dmx(Dmx<'a>),
    Sync,
}

#[derive(Debug)]
pub enum Error<'a> {
    InvalidNet,
    InvalidSubnet,
    InvalidUniverse,
    UnsupportedProtocolVersion(u16),
    UnsupportedOpCode(u16),
    /// The amount of data specified in the packet metadata does not match the actual data
    /// received.  
    InvalidDataLength,
    ParserError(nom::Err<nom::error::Error<&'a [u8]>>),
}

impl core::fmt::Display for Error<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InvalidNet => f.write_str("InvalidNet"),
            Error::InvalidSubnet => f.write_str("InvalidSubnet"),
            Error::InvalidUniverse => f.write_str("InvalidUniverse"),
            Error::InvalidDataLength => f.write_str("InvalidDataLength"),
            Error::UnsupportedProtocolVersion(version) => f
                .debug_tuple("UnsupportedProtocolVersion")
                .field(version)
                .finish(),
            Error::UnsupportedOpCode(code) => {
                f.debug_tuple("UnsupportedOpCode").field(code).finish()
            }
            Error::ParserError(err) => f.debug_tuple("ParserError").field(err).finish(),
        }
    }
}

impl<'a> From<nom::Err<nom::error::Error<&'a [u8]>>> for Error<'a> {
    fn from(err: nom::Err<nom::error::Error<&'a [u8]>>) -> Self {
        Error::ParserError(err)
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug)]
pub struct Sequence(u8);

impl Default for Sequence {
    fn default() -> Self {
        Self(1)
    }
}

impl Deref for Sequence {
    type Target = u8;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Sequence> for u8 {
    fn from(value: Sequence) -> Self {
        value.0
    }
}

impl core::fmt::Display for Sequence {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("{}", self.0))
    }
}

impl Sequence {
    pub fn new(value: u8) -> Option<Self> {
        if value == 0 {
            None
        } else {
            Some(Self(value))
        }
    }
    pub fn increment(&mut self) {
        self.0 = self.0.wrapping_add(1);
        // value 0 is to set to disable this feature.
        // We have options
        if self.0 == 0 {
            self.0 = 1;
        }
    }
}

impl<'a> Art<'a> {
    pub fn from_slice(buf: &'a [u8]) -> Result<Self, Error<'a>> {
        // ID
        let (s, _) = tag(ID)(buf)?;

        let (s, op_code) = le_u16(s)?;

        // not all packets have a protocol number

        if [
            codes::OP_POLL,
            codes::OP_COMMAND,
            codes::OP_DMX,
            codes::OP_SYNC,
        ]
        .contains(&op_code)
        {
            let (s, protocol_version): (&'a [u8], u16) = be_u16(s)?;

            if protocol_version > PROTOCOL_VERSION {
                return Err(Error::UnsupportedProtocolVersion(protocol_version));
            }

            let message = match op_code {
                codes::OP_POLL => Art::Poll(parse_poll(s)?),
                codes::OP_COMMAND => Art::Command(parse_command(s)?),
                codes::OP_DMX => Art::Dmx(parse_dmx(s)?),
                codes::OP_SYNC => parse_sync(s).map(|_| Art::Sync)?,
                _ => unreachable!(),
            };

            Ok(message)
        } else {
            Err(Error::UnsupportedOpCode(op_code))
        }
    }
    pub fn op_code(&self) -> u16 {
        match self {
            Art::Poll(_) => codes::OP_POLL,
            Art::Command(_) => codes::OP_COMMAND,
            Art::Dmx(_) => codes::OP_DMX,
            Art::Sync => codes::OP_SYNC,
            Art::PollReply(_) => codes::OP_POLL_REPLY,
        }
    }
    pub fn serialize(&self, buf: &mut [u8]) {
        let offset = &mut 0;
        buf.write::<&[u8]>(offset, ID).unwrap();
        buf.write_with::<u16>(offset, self.op_code(), LE).unwrap();
        buf.write::<u16>(offset, PROTOCOL_VERSION).unwrap();
        match self {
            Art::Dmx(dmx) => {
                dmx.serialize(&mut buf[*offset..]);
            }
            Art::Sync => buf.write::<u16>(offset, 0).unwrap(),

            // TODO: implement remaining packets as well
            Art::PollReply(_) | Art::Poll(_) | Art::Command(_) => unimplemented!(),
        }
    }
}

/// (ESTAManLo, ESTAManHi)
pub type ESTAManufacturerCode = (char, char);

fn parse_esta_manufacturer_code<'a>(s: &'a [u8]) -> IResult<&'a [u8], ESTAManufacturerCode> {
    let (s, (lo, hi)) = tuple((number::u8, number::u8))(s)?;
    Ok((s, (lo as char, hi as char)))
}

pub fn put_esta_manufacturer_code(
    buf: &mut [u8],
    manufacturer_code: &ESTAManufacturerCode,
) {
    let offset = &mut 0;
    buf.write::<u8>(offset, manufacturer_code.0 as u8).unwrap();
    buf.write::<u8>(offset, manufacturer_code.1 as u8).unwrap();
}

/// One of the 32,768 possible addresses to which a DMX frame can be
/// directed. The Port-Address is a 15-bit number composed of Net+Sub-Net+Universe.
///
/// Bits:
///     | 15 | 8-14 | 4-7    | 0-3      |
///     | 0  | Net  | SubNet | Universe |
#[derive(PartialEq, Eq, Debug, Hash, Clone, Copy)]
pub struct PortAddress {
    net: u8,
    sub_net: u8,
    universe: u8,
}

fn parse_port_address<'a>(s: &'a [u8]) -> IResult<&'a [u8], PortAddress> {
    use nom::bits::complete as bits;

    let (s, (sub_net, universe, _, net)): (&[u8], (u8, u8, u8, u8)) = nom::bits::bits(tuple((
        // Low Byte (SubUni)
        bits::take::<&[u8], u8, usize, nom::error::Error<(&[u8], usize)>>(4usize),
        bits::take(4usize),
        // High Byte (Net)
        bits::take(1usize),
        bits::take(7usize),
    )))(s)?;

    let port_address = PortAddress {
        net,
        sub_net,
        universe,
    };

    Ok((s, port_address))
}

impl PortAddress {
    pub fn new(net: u8, sub_net: u8, universe: u8) -> Result<Self, Error<'static>> {
        if net > 127 {
            return Err(Error::InvalidNet);
        }

        if sub_net > 15 {
            return Err(Error::InvalidSubnet);
        }

        if universe > 15 {
            return Err(Error::InvalidUniverse);
        }

        Ok(Self {
            net,
            sub_net,
            universe,
        })
    }

    // Combines the Net, SubNet and Universe into a single usize index. Note this is not the same as the little endian u16 sent over the wire.
    pub fn as_index(&self) -> usize {
        (self.net as usize >> 14) + (self.sub_net as usize >> 7) + (self.universe as usize)
    }

    pub(crate) fn serialize(&self, offset: &mut usize, buf: &mut [u8]) {
        buf.write::<u8>(offset, self.universe + (self.sub_net << 4));

        // we do not need to check this is within range because it can only be parsed correctly
        buf.write::<u8>(offset, self.net);
    }

    pub fn net(&self) -> u8 {
        self.net
    }

    pub fn sub_net(&self) -> u8 {
        self.sub_net
    }

    pub fn universe(&self) -> u8 {
        self.universe
    }
}

// Appends a Nul terminated ASCII string truncated (or padded) to N bytes
fn put_padded_str<const N: usize>(offset: &mut usize, buf: &mut [u8], input: &str) {
    let mut padded_bytes = [0; N];

    let bytes = input.as_bytes();
    // Truncate to N minus 1 to leave 1 byte for the NUL character
    let truncated_bytes = if bytes.len() > N - 1 {
        &bytes[..N - 1]
    } else {
        &bytes[..]
    };

    // Put the truncated bytes into the padded buffer - this guarentees that the length is always N
    (&mut padded_bytes[..]).write::<&[u8]>(offset, truncated_bytes);

    buf.write::<&[u8]>(offset, &padded_bytes);
}

#[derive(Debug)]
pub struct Poll {
    pub flags: u8,
    pub min_diagnostic_priority: u8,
    pub target_port_addresses: RangeInclusive<u16>,
}

fn parse_poll<'a>(s: &'a [u8]) -> Result<Poll, Error<'a>> {
    let (s, flags) = number::u8(s)?;
    let (s, min_diagnostic_priority) = number::u8(s)?;

    let target_port_addresses = if !s.is_empty() {
        let (s, target_port_top): (&'a [u8], u16) = be_u16(s)?;
        let (_s, target_port_bottom): (&'a [u8], u16) = be_u16(s)?;

        target_port_top..=target_port_bottom
    } else {
        0..=u16::MAX
    };

    Ok(Poll {
        flags,
        min_diagnostic_priority,
        target_port_addresses,
    })
}

#[derive(Debug)]
pub struct Command<'a> {
    pub esta_manufacturer_code: ESTAManufacturerCode,
    pub data: &'a [u8],
}

fn parse_command<'a>(s: &'a [u8]) -> Result<Command<'a>, Error<'a>> {
    let (s, esta_manufacturer_code) = parse_esta_manufacturer_code(s)?;
    let (s, length): (&'a [u8], u16) = le_u16(s)?;

    let data = &s[..length as usize];

    Ok(Command {
        esta_manufacturer_code,
        data,
    })
}

#[derive(PartialEq, Eq, Debug)]
pub struct Dmx<'a> {
    /// The sequence number is used to ensure that
    /// ArtDmx packets are used in the correct order.
    /// When Art-Net is carried over a medium such as
    /// the Internet, it is possible that ArtDmx packets
    /// will reach the receiver out of order.
    ///
    /// This field is incremented in the range 0x01 to
    /// 0xff to allow the receiving node to re-sequence
    /// packets.
    ///
    /// The Sequence field is set to 0x00 to disable this
    /// feature.
    pub sequence: Option<Sequence>,
    /// The physical input port from which DMX512
    /// data was input. This field is used by the
    /// receiving device to discriminate between
    /// packets with identical Port-Address that have
    /// been generated by different input ports and so
    /// need to be merged.
    pub physical: u8,
    ///  one of the 32,768 possible addresses to which a DMX frame can be
    /// directed. The Port-Address is a 15-bit number composed of Net+Sub-Net+Universe.
    ///
    /// Bits:
    ///     | 15 | 8-14 | 4-7    | 0-3      |
    ///     | 0  | Net  | SubNet | Universe |
    pub port_address: PortAddress,
    pub data: &'a [u8],
}

impl<'a> Dmx<'a> {
    fn serialize(&self, buf: &mut [u8]) {
        let offset = &mut 0;
        let data_len = self.data.len();
        buf.write::<u8>(offset, self.sequence.map(|seq| seq.into()).unwrap_or_default());
        buf.write::<u8>(offset, self.physical);
        self.port_address.serialize(offset, buf);
        buf.write_with::<u16>(offset, data_len as u16, BE);
        buf.write::<&[u8]>(offset, self.data);
    }
}

impl<'a> core::fmt::Display for Dmx<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!(
            "ArtDMX Universe = {} Seq: {:width$} Data: [{:width$}] [{:width$}] [{:width$}] [{:width$}] [...]",
            self.port_address.universe(),
            self.sequence.map(Into::<u8>::into).unwrap_or_default(),
            &self.data[0],
            &self.data[1],
            &self.data[2],
            &self.data[3],
            width = 3
        ))
    }
}

fn parse_dmx<'a>(s: &'a [u8]) -> Result<Dmx<'a>, Error<'a>> {
    let (s, sequence) = number::u8(s)?;
    let (s, physical) = number::u8(s)?;
    let (s, port_address) = parse_port_address(s)?;

    let (s, length): (&'a [u8], u16) = be_u16(s)?;

    if length as usize > s.len() {
        return Err(Error::InvalidDataLength);
    }

    let data = &s[..length as usize];

    Ok(Dmx {
        sequence: Sequence::new(sequence),
        physical,
        port_address,
        data,
    })
}

fn parse_sync<'a>(s: &'a [u8]) -> Result<(), Error<'a>> {
    let (s, _aux1) = number::u8(s)?;
    let (_s, _aux2) = number::u8(s)?;

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn port_addr_roundtrip() {
        let addr = PortAddress::new(123, 5, 8).unwrap();
        let mut buf = [0; 1024];
        addr.serialize(&mut 0, &mut buf);
        let (_, output) = parse_port_address(&buf).unwrap();

        assert_eq!(output, addr);
    }

    #[test]
    fn dmx_roundtrip() {
        let data = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        let dmx = Dmx {
            data,
            sequence: Sequence::new(42),
            physical: 5,
            port_address: PortAddress::new(13, 3, 2).unwrap(),
        };

        let mut buf = [0; 1024];

        dmx.serialize(&mut buf);
        let output = parse_dmx(&buf).unwrap();
        assert_eq!(dmx, output);
    }
}
