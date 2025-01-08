use clap::Parser;

const PTRACE_SYSCALL_NUBMER: i32 = 101;
const WAIT4_SYSCALL_NUBMER: i32 = 61;
const WRITE_SYSCALL_NUBMER: i32 = 1;

#[derive(Parser)]
struct Options {
    #[clap(short, long)]
    pid: i32,
}

enum PtraceRequest {
    Attach = 16,
    Syscall = 24,
    Regs = 12,
    PeekData = 2,
}

#[allow(non_camel_case_types)]
type c_ulonglong = u64;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Regs {
    pub r15: c_ulonglong,
    pub r14: c_ulonglong,
    pub r13: c_ulonglong,
    pub r12: c_ulonglong,
    pub rbp: c_ulonglong,
    pub rbx: c_ulonglong,
    pub r11: c_ulonglong,
    pub r10: c_ulonglong,
    pub r9: c_ulonglong,
    pub r8: c_ulonglong,
    pub rax: c_ulonglong,
    pub rcx: c_ulonglong,
    pub rdx: c_ulonglong,
    pub rsi: c_ulonglong,
    pub rdi: c_ulonglong,
    pub orig_rax: c_ulonglong,
    pub rip: c_ulonglong,
    pub cs: c_ulonglong,
    pub eflags: c_ulonglong,
    pub rsp: c_ulonglong,
    pub ss: c_ulonglong,
    pub fs_base: c_ulonglong,
    pub gs_base: c_ulonglong,
    pub ds: c_ulonglong,
    pub es: c_ulonglong,
    pub fs: c_ulonglong,
    pub gs: c_ulonglong,
}

unsafe fn ptrace_syscall(pid: i32, request: PtraceRequest, address: *mut (), data: *mut ()) -> i32 {
    let result;
    std::arch::asm!(
        "syscall",
        in("rax") PTRACE_SYSCALL_NUBMER,
        in("rdi") request as usize,
        in("rsi") pid,
        in("rdx") address,
        in("r10") data,
        lateout("rax") result,
    );
    result
}

unsafe fn wait4_syscall(pid: i32) -> i32 {
    let result;
    std::arch::asm!(
        "syscall",
        in("rax") WAIT4_SYSCALL_NUBMER,
        in("rdi") pid,
        in("rsi") 0,
        in("rdx") 0,
        in("r10") 0,
        lateout("rax") result,
    );
    result
}

unsafe fn trace_process(pid: i32) {
    println!("Tracing process with PID: {}", pid);
    ptrace_syscall(
        pid,
        PtraceRequest::Attach,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    );
    wait4_syscall(pid);

    let mut is_entering_syscall = false;

    loop {
        ptrace_syscall(
            pid,
            PtraceRequest::Syscall,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        wait4_syscall(pid);
        let mut regs = std::mem::zeroed::<Regs>();
        ptrace_syscall(
            pid,
            PtraceRequest::Regs,
            std::ptr::null_mut(),
            &mut regs as *mut _ as *mut (),
        );
        if regs.orig_rax == WRITE_SYSCALL_NUBMER as u64 {
            if !is_entering_syscall {
                let buffer = (0..regs.rdx)
                    .map(|shift| {
                        let mut data = 0u8;
                        ptrace_syscall(
                            pid,
                            PtraceRequest::PeekData,
                            (regs.rsi + shift) as *mut (),
                            &mut data as *mut _ as *mut (),
                        );
                        data as char
                    })
                    .collect::<String>();
                println!("FD: {fd}: {buffer:?}", fd = regs.rdi);
            }
            is_entering_syscall = !is_entering_syscall;
        }
    }
}

fn main() {
    let options = Options::parse();
    unsafe {
        trace_process(options.pid);
    }
}
