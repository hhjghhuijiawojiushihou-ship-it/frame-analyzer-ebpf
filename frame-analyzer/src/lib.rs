/*
* Copyright (c) 2024 shadow3aaa@gitbub.com
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

#![warn(clippy::nursery, clippy::all, clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation
)]

pub mod c_api;

mod analyze_target;
mod ebpf;
mod error;
mod uprobe;

use std::{
    collections::{HashMap, VecDeque},
    os::unix::io::AsRawFd,
    time::Duration,
};

use mio::{event::Event, Events, Interest, Poll, Token, unix::SourceFd};

use analyze_target::AnalyzeTarget;
pub use error::AnalyzerError;
use error::Result;
use uprobe::UprobeHandler;

pub type Pid = i32;

const EVENT_MAX: usize = 1024;

pub struct Analyzer {
    poll: Option<Poll>,
    map: HashMap<Pid, AnalyzeTarget>,
    buffer: VecDeque<Pid>,
}

impl Analyzer {
    pub fn new() -> Result<Self> {
        let poll = None;
        let map = HashMap::new();
        let buffer = VecDeque::with_capacity(EVENT_MAX);

        Ok(Self { poll, map, buffer })
    }

    pub fn attach_app(&mut self, pid: Pid) -> Result<()> {
        if self.map.contains_key(&pid) {
            return Ok(());
        }

        let uprobe = UprobeHandler::attach_app(pid)?;
        self.map.insert(pid, AnalyzeTarget::new(uprobe));
        self.register_poll()?;

        Ok(())
    }

    pub fn detach_app(&mut self, pid: Pid) -> Result<()> {
        if !self.map.contains_key(&pid) {
            return Ok(());
        }

        self.map.remove(&pid).ok_or(AnalyzerError::AppNotFound)?;
        self.buffer.retain(|pid_event| *pid_event != pid);
        self.register_poll()?;

        Ok(())
    }

    pub fn detach_apps(&mut self) {
        self.map.clear();
        self.buffer.clear();
    }

    pub fn recv(&mut self) -> Option<(Pid, Duration)> {
        if self.buffer.is_empty() {
            if let Some(ref mut poll) = self.poll {
                let mut events = Events::with_capacity(EVENT_MAX);
                let _ = poll.poll(&mut events, None);

                self.buffer.extend(events.iter().map(event_to_pid));
            }

            let _ = self.register_poll();
        }

        let pid = self.buffer.pop_front()?;
        let frametime = self.map.get_mut(&pid)?.update()?;

        Some((pid, frametime))
    }

    pub fn recv_timeout(&mut self, time: Duration) -> Option<(Pid, Duration)> {
        if self.buffer.is_empty() {
            if let Some(ref mut poll) = self.poll {
                let mut events = Events::with_capacity(EVENT_MAX);
                let _ = poll.poll(&mut events, Some(time));

                self.buffer.extend(events.iter().map(event_to_pid));
            }

            let _ = self.register_poll();
        }

        let pid = self.buffer.pop_front()?;
        let frametime = self.map.get_mut(&pid)?.update()?;

        Some((pid, frametime))
    }

    #[must_use]
    pub fn contains(&self, app: Pid) -> bool {
        self.map.contains_key(&app)
    }

    pub fn pids(&self) -> impl Iterator<Item = Pid> + '_ {
        self.map.keys().copied()
    }

    fn register_poll(&mut self) -> Result<()> {
        let poll = if let Some(existing) = self.poll.take() {
            existing
        } else {
            Poll::new()?
        };

        for (pid, handler) in &mut self.map {
            poll.registry().register(
                &mut SourceFd(&handler.uprobe.ring()?.as_raw_fd()),
                Token(*pid as usize),
                Interest::READABLE,
            )?;
        }

        self.poll = Some(poll);
        Ok(())
    }
}

fn event_to_pid(event: &Event) -> Pid {
    let Token(pid) = event.token();
    pid as Pid
}
