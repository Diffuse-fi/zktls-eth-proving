use std::{ffi::CString, ptr};

use pprof::{ProfilerGuard, Report};
use sgx_ocalls::bindings::ocall_write_to_file;

pub fn profile<F, T>(freq_hz: i32, filename: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    let guard = ProfilerGuard::new(freq_hz).expect("start profiler");

    let out = f();

    if let Ok(report) = guard.report().build() {
        let mut svg = Vec::<u8>::new();
        report.flamegraph(&mut svg).expect("flamegraph");

        unsafe {
            ocall_write_to_file(
                svg.as_ptr() as *const u8,
                svg.len(),
                CString::new(filename).unwrap().as_ptr() as *const u8,
                filename.len(),
            );
        }
    }
    out
}
