use nix::mqueue::{mq_open, mq_receive, mq_send, MQ_OFlag, MqAttr, MqdT};
use nix::sys::stat::Mode;
use std::os::fd::AsFd;
use std::time::Duration;

use osal::error::ErrorType;
use osal::ipc::{IpcWaitResult, IpcSyscalls};

pub struct PosixIpc {
    queue: MqdT,
}

impl PosixIpc {
    pub fn new(name: &str) -> nix::Result<Self> {
        let attr = MqAttr::new(10, 128, 0, 0);
        let queue = mq_open(name, MQ_OFlag::O_CREAT | MQ_OFlag::O_RDWR, Mode::from_bits_truncate(0o644), Some(&attr))?;
        Ok(Self { queue })
    }
}

#[derive(Debug)]
pub struct NixIpcError;
impl osal::error::Error for NixIpcError {
    fn kind(&self) -> osal::error::ErrorKind {
        osal::error::ErrorKind::Other
    }
}
impl ErrorType for PosixIpc {
    type Error = NixIpcError;
}


impl IpcSyscalls for PosixIpc {
    type TargetId = String;
    type IpcFlags = ();
    type ReplyContext = ();

    fn ipc_send(
        &self,
        _target: Self::TargetId,
        message: impl AsRef<[u8]>,
        _flags: Option<Self::IpcFlags>,
    ) -> Result<(), Self::Error> {
        mq_send(&self.queue, message.as_ref(), 0).unwrap();
        Ok(())
    }

    fn ipc_reply(
        &self,
        _reply_context: Option<&Self::ReplyContext>,
        mut message: impl AsMut<[u8]>,
        _flags: Option<Self::IpcFlags>,
    ) -> Result<(), Self::Error> {
        mq_send(&self.queue, message.as_mut(), 0).unwrap();
        Ok(())
    }

    fn ipc_rcv(
        &self,
        mut message: impl AsMut<[u8]>,
        _notification_mask: u32,
        _sender_filter: Option<u32>,
        timeout: Option<Duration>,
    ) -> Result<IpcWaitResult, Self::Error> {
        if let Some(duration) = timeout {
            let fd = self.queue.as_fd();
            let mut pollfd = [nix::poll::PollFd::new(fd, nix::poll::PollFlags::POLLIN)];
            let timeout_ms = if duration.as_millis() > u16::MAX as u128 {
                u16::MAX
            } else {
                duration.as_millis() as u16
            };
            nix::poll::poll(&mut pollfd, Some(timeout_ms)).unwrap();
        }

        let buf = message.as_mut();
        let mut msg_prio = 0;
        let _prio = mq_receive(&self.queue, buf, &mut msg_prio);
        Ok(IpcWaitResult::MsgRcvd)
    }
}
