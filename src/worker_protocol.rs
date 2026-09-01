//! Versioned worker-control records and `SCM_RIGHTS` endpoint transfer.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::{
    ffi::c_void,
    fs::File,
    io,
    os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
};

pub(crate) const STATE_DIRECTORY_ENV: &str = "STATE_DIRECTORY";
const CONTROL_FD: i32 = 3;
const MAGIC: [u8; 4] = *b"UGSP";
const VERSION: u8 = 1;
const HEADER_LENGTH: usize = 20;
const MAX_BODY_LENGTH: usize = 1024 * 1024;
const MAX_DESCRIPTORS: usize = 32;
#[cfg(target_os = "linux")]
const RECEIVE_DESCRIPTOR_FLAGS: libc::c_int = libc::MSG_CMSG_CLOEXEC;
#[cfg(not(target_os = "linux"))]
const RECEIVE_DESCRIPTOR_FLAGS: libc::c_int = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum Kind {
    InitialResources = 0x01,
    UsbEndpoints = 0x02,
    UsbBusEvent = 0x03,
    UsbControlRequest = 0x04,
    Quiesce = 0x11,
    ConfigurationRejected = 0x12,
    Configure = 0x80,
    UsbControlResponse = 0x81,
    Serving = 0x82,
    Quiesced = 0x84,
}

pub(crate) struct Record {
    pub(crate) kind: Kind,
    pub(crate) generation: u32,
    pub(crate) request_id: u32,
    pub(crate) body: Vec<u8>,
    pub(crate) files: Vec<File>,
}

impl Record {
    pub(crate) fn new(kind: Kind, generation: u32, request_id: u32, body: Vec<u8>) -> Self {
        Self {
            kind,
            generation,
            request_id,
            body,
            files: Vec::new(),
        }
    }
}

pub(crate) struct Channel<'descriptor> {
    descriptor: BorrowedFd<'descriptor>,
}

impl Channel<'static> {
    pub(crate) fn from_fixed_descriptor() -> Self {
        Self {
            // SAFETY: the supervisor installs FD 3 before executing a worker.
            descriptor: unsafe { BorrowedFd::borrow_raw(CONTROL_FD) },
        }
    }
}

impl Channel<'_> {
    pub(crate) fn as_raw_fd(&self) -> i32 {
        self.descriptor.as_raw_fd()
    }

    pub(crate) fn send(&self, record: &Record) -> io::Result<()> {
        if !record.files.is_empty() || record.body.len() > MAX_BODY_LENGTH {
            return invalid("invalid outbound worker-control record");
        }
        let mut packet = Vec::with_capacity(HEADER_LENGTH + record.body.len());
        packet.extend_from_slice(&MAGIC);
        packet.extend_from_slice(&[VERSION, record.kind as u8]);
        packet.extend_from_slice(&0_u16.to_be_bytes());
        packet.extend_from_slice(&record.generation.to_be_bytes());
        packet.extend_from_slice(&record.request_id.to_be_bytes());
        packet.extend_from_slice(&(record.body.len() as u32).to_be_bytes());
        packet.extend_from_slice(&record.body);
        // SAFETY: packet points to initialized memory for the duration of send.
        let length = unsafe {
            libc::send(
                self.descriptor.as_raw_fd(),
                packet.as_ptr().cast::<c_void>(),
                packet.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if length < 0 {
            return Err(io::Error::last_os_error());
        }
        if length as usize != packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "worker-control record was not sent atomically",
            ));
        }
        Ok(())
    }

    pub(crate) fn receive(&self) -> io::Result<Record> {
        let mut packet = vec![0_u8; HEADER_LENGTH + MAX_BODY_LENGTH + 1];
        let mut control = vec![
            0_u8;
            // SAFETY: CMSG_SPACE is a pure size calculation.
            unsafe {
                libc::CMSG_SPACE(
                    (MAX_DESCRIPTORS * std::mem::size_of::<libc::c_int>()) as libc::c_uint,
                ) as usize
            }
        ];
        let mut iovec = libc::iovec {
            iov_base: packet.as_mut_ptr().cast::<c_void>(),
            iov_len: packet.len(),
        };
        // SAFETY: zero is a valid initial msghdr representation.
        let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
        header.msg_iov = &mut iovec;
        header.msg_iovlen = 1;
        header.msg_control = control.as_mut_ptr().cast::<c_void>();
        header.msg_controllen = control.len() as _;
        // SAFETY: header owns writable packet and ancillary buffers.
        let length = unsafe {
            libc::recvmsg(
                self.descriptor.as_raw_fd(),
                &mut header,
                RECEIVE_DESCRIPTOR_FLAGS,
            )
        };
        if length < 0 {
            return Err(io::Error::last_os_error());
        }
        if length == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "worker-control channel closed",
            ));
        }
        if header.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
            || (length as usize) < HEADER_LENGTH
        {
            return invalid("truncated worker-control record");
        }
        packet.truncate(length as usize);
        if packet[..4] != MAGIC || packet[4] != VERSION {
            return invalid("invalid worker-control header");
        }
        let kind = Kind::from_byte(packet[5])?;
        let declared_files = u16::from_be_bytes(packet[6..8].try_into().unwrap()) as usize;
        let generation = u32::from_be_bytes(packet[8..12].try_into().unwrap());
        let request_id = u32::from_be_bytes(packet[12..16].try_into().unwrap());
        let body_length = u32::from_be_bytes(packet[16..20].try_into().unwrap()) as usize;
        if body_length > MAX_BODY_LENGTH || packet.len() != HEADER_LENGTH + body_length {
            return invalid("invalid worker-control body length");
        }

        let mut descriptors = Vec::<OwnedFd>::new();
        // SAFETY: ancillary pointers are produced by recvmsg within control.
        unsafe {
            let mut ancillary = libc::CMSG_FIRSTHDR(&header);
            while !ancillary.is_null() {
                if (*ancillary).cmsg_level != libc::SOL_SOCKET
                    || (*ancillary).cmsg_type != libc::SCM_RIGHTS
                {
                    return invalid("unexpected ancillary worker-control data");
                }
                let base = libc::CMSG_LEN(0) as usize;
                let ancillary_length = (*ancillary).cmsg_len as usize;
                if ancillary_length < base
                    || !(ancillary_length - base).is_multiple_of(std::mem::size_of::<libc::c_int>())
                {
                    return invalid("malformed SCM_RIGHTS payload");
                }
                let count = (ancillary_length - base) / std::mem::size_of::<libc::c_int>();
                let source = libc::CMSG_DATA(ancillary).cast::<libc::c_int>();
                for index in 0..count {
                    descriptors.push(OwnedFd::from_raw_fd(*source.add(index)));
                }
                ancillary = libc::CMSG_NXTHDR(&header, ancillary);
            }
        }
        if descriptors.len() != declared_files || descriptors.len() > MAX_DESCRIPTORS {
            return invalid("worker-control descriptor count mismatch");
        }
        Ok(Record {
            kind,
            generation,
            request_id,
            body: packet.split_off(HEADER_LENGTH),
            files: descriptors.into_iter().map(File::from).collect(),
        })
    }
}

impl Kind {
    fn from_byte(value: u8) -> io::Result<Self> {
        match value {
            0x01 => Ok(Self::InitialResources),
            0x02 => Ok(Self::UsbEndpoints),
            0x03 => Ok(Self::UsbBusEvent),
            0x04 => Ok(Self::UsbControlRequest),
            0x11 => Ok(Self::Quiesce),
            0x12 => Ok(Self::ConfigurationRejected),
            0x80 => Ok(Self::Configure),
            0x81 => Ok(Self::UsbControlResponse),
            0x82 => Ok(Self::Serving),
            0x84 => Ok(Self::Quiesced),
            _ => invalid(format!("unknown worker-control kind 0x{value:02x}")),
        }
    }
}

pub(crate) fn validate_initial_resources(record: Record) -> io::Result<Vec<(String, File)>> {
    if record.kind != Kind::InitialResources || record.generation != 0 || record.request_id != 0 {
        return invalid("expected initial worker resources");
    }
    if record.body.len() < 2 {
        return invalid("invalid initial resource-name table");
    }
    let count = u16::from_be_bytes(record.body[..2].try_into().unwrap()) as usize;
    if count != record.files.len() {
        return invalid("initial resource names and descriptors differ");
    }
    let mut offset = 2;
    let mut names = Vec::with_capacity(count);
    for _ in 0..count {
        let length = record
            .body
            .get(offset..offset + 2)
            .ok_or_else(|| data_error("truncated initial resource name"))?;
        offset += 2;
        let length = u16::from_be_bytes(length.try_into().unwrap()) as usize;
        let bytes = record
            .body
            .get(offset..offset + length)
            .ok_or_else(|| data_error("truncated initial resource name"))?;
        offset += length;
        names.push(
            std::str::from_utf8(bytes)
                .map_err(|_| data_error("initial resource name is not UTF-8"))?
                .to_owned(),
        );
    }
    if offset != record.body.len() {
        return invalid("initial resource-name table has trailing data");
    }
    Ok(names.into_iter().zip(record.files).collect())
}

fn invalid<T>(message: impl Into<String>) -> io::Result<T> {
    Err(data_error(message))
}

fn data_error(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
