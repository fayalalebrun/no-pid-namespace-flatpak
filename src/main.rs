use std::{ffi::c_void, ops::Range, os::unix::process::CommandExt, process::Command};

use nix::{
    libc::user_regs_struct,
    sys::{
        ptrace::{self, traceme, Options},
        wait::waitpid,
    },
    unistd::Pid,
};

const USIZE_SIZE: usize = std::mem::size_of::<usize>();

struct WriteArgs {
    pub addr: usize,
    contents: Vec<u8>,
    orig_regs: user_regs_struct,
    pid: Pid,
}

impl WriteArgs {
    pub fn parse(pid: Pid, regs: user_regs_struct) -> Option<Self> {
        if regs.orig_rax == 1 {
            let addr = regs.rsi as usize;
            let len = regs.rdx as usize;
            Some(Self {
                addr,
                orig_regs: regs,
                pid,
                contents: read_buffer(pid, len, addr),
            })
        } else {
            None
        }
    }

    pub fn contents(&self) -> &[u8] {
        &self.contents
    }

    pub fn remove_region(&mut self, range: Range<usize>) {
        self.contents.drain(range);
    }

    pub fn write_out(self) {
        self.contents[..]
            .chunks(USIZE_SIZE)
            .enumerate()
            .for_each(|(i, chunk)| unsafe {
                let addr = (self.addr + i * USIZE_SIZE) as *mut c_void;
                let mut data = [0u8; USIZE_SIZE];
                // Unlikely to be a problem, but just in case try to preserve previous memory
                if chunk.len() < USIZE_SIZE {
                    data = ptrace::read(self.pid, addr).unwrap().to_le_bytes();
                }
                data[..chunk.len()].copy_from_slice(chunk);
                ptrace::write(self.pid, addr, usize::from_le_bytes(data) as *mut c_void).unwrap();
            });

        let mut regs = self.orig_regs;
        regs.rdx = self.contents.len() as u64;
        ptrace::setregs(self.pid, regs).unwrap();
    }
}

fn read_buffer(pid: Pid, len: usize, addr: usize) -> Vec<u8> {
    let add = if len % USIZE_SIZE == 0 { 0 } else { 1 };
    let vec: Vec<_> = (0..(len / USIZE_SIZE) + add)
        .flat_map(|i| {
            ptrace::read(pid, (addr + i * USIZE_SIZE) as *mut c_void)
                .unwrap()
                .to_le_bytes()
                .into_iter()
        })
        .take(len)
        .collect();
    vec
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn main() {
    let argv: Vec<_> = std::env::args().collect();
    let mut cmd = Command::new(&argv[1]);

    cmd.args(&argv[2..]);

    unsafe { cmd.pre_exec(|| traceme().map_err(|e| e.into())) };

    let mut child = cmd.spawn().expect("child process failed");

    let pid = Pid::from_raw(child.id() as i32);

    ptrace::setoptions(
        pid,
        Options::PTRACE_O_TRACESYSGOOD | Options::PTRACE_O_TRACEEXEC,
    )
    .unwrap();

    waitpid(pid, None).unwrap();

    // Every syscall causes two interruptions, on exit and on entry.
    let mut exit = false;

    let search_for = &["--unshare-pid".as_bytes(), &[0]].concat();

    loop {
        ptrace::syscall(pid, None).unwrap();
        let status = waitpid(pid, None).unwrap();

        if matches!(status, nix::sys::wait::WaitStatus::PtraceSyscall(_)) {
            //get the registers from the address where ptrace is stopped.
            let regs = match ptrace::getregs(pid) {
                Ok(x) => x,
                Err(err) => {
                    eprintln!("End of ptrace with string not found {:?}", err);
                    break;
                }
            };

            match WriteArgs::parse(pid, regs) {
                Some(mut args) if !exit => {
                    dbg!(String::from_utf8_lossy(args.contents()));
                    if let Some(idx) = find_subsequence(args.contents(), search_for) {
                        // Remove the found region
                        args.remove_region(idx..idx + search_for.len());
                        args.write_out();
                        println!("Bingo, removing");
                        break;
                    }
                }
                _ => {}
            }

            exit = !exit;
        }
    }

    ptrace::detach(pid, None).unwrap();

    println!("Waiting for child");

    child.wait().unwrap();
}
