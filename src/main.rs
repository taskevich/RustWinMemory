use std::ffi::c_void;

use::windows::Win32::{
    System::{
        Diagnostics::{
            ToolHelp::{
                CreateToolhelp32Snapshot,
                Process32First,
                Process32Next,
                CREATE_TOOLHELP_SNAPSHOT_FLAGS,
                PROCESSENTRY32
            },
            Debug::{
                WriteProcessMemory,
                ReadProcessMemory
            }
        },
        Threading::{
            OpenProcess,
            PROCESS_ALL_ACCESS
        }
    },
    Foundation::HANDLE
};


struct Memory
{
    pe: PROCESSENTRY32,
    process: Option<HANDLE>
}


impl Memory {
    fn default() -> Self {
        let mut pe = PROCESSENTRY32::default();
        pe.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

        Memory { pe: pe, process: None }
    }

    fn find_process(&self, target_name: &str) -> Option<u32> {
        unsafe {
            let snap = CreateToolhelp32Snapshot(
                CREATE_TOOLHELP_SNAPSHOT_FLAGS(0x2), 
                0
            ).unwrap();
            
            let mut pe = self.pe;

            let _process = Process32First(
                snap, 
                &mut pe as *mut PROCESSENTRY32
            );

            loop {
                let next = Process32Next(
                    snap, 
                    &mut pe as *mut PROCESSENTRY32
                );

                match next {
                    Ok(_) => {
                        let process_name = String::from_utf8_lossy(&pe.szExeFile).to_lowercase();
                        
                        if process_name.contains(target_name) {
                            return Some(pe.th32ProcessID);
                        }
                    },
                    Err(_) => {
                        break;
                    }
                }
            }
        }
        None
    }

    fn open_process_by_pid(&mut self, pid: u32) -> bool {
        unsafe {
            let process = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
            match process {
                Ok(handle) => {
                    self.process = Some(handle);
                    return true;
                }
                Err(e) => {
                    println!("Cannot open process: {}", e);
                }
            }
        }
        false
    }

    fn wpm(&self, baseaddr: *const c_void, buffer: *const c_void, nsize: usize, lpnumberofbyteswritten: Option<*mut usize>) -> bool {
        unsafe {
            match WriteProcessMemory(self.process.unwrap(), baseaddr, buffer, nsize, lpnumberofbyteswritten) {
                Ok(_) => return true,
                Err(e) => {
                    println!("Cannot write to memory: {:?}", e);
                    return false;
                }
            }
        }
    }

    fn rpm(&self, baseaddr: *const c_void, buffer: *mut c_void, nsize: usize, lpnumberofbyteswritten: Option<*mut usize>) -> bool {
        unsafe {
            match ReadProcessMemory(self.process.unwrap(), baseaddr, buffer, nsize, lpnumberofbyteswritten) {
                Ok(_) => return true,
                Err(e) => {
                    println!("Cannot read memory by {:?} address: {:?}", baseaddr, e);
                    return false;
                }
            }
        }
    }
}


fn main() {
    let mut m = Memory::default();

    if let Some(pid) = m.find_process("purevpn") {
        println!("Process id was found {}", pid);

        if m.open_process_by_pid(pid) {
            println!("Process was opened");

            if let Some(_process) = m.process {
                m.wpm(
                    0x90 as *const c_void, 
                    "helloworld".as_ptr() as *const c_void, 
                    "helloworld".len(), 
                    None);
            }
        }
    }
}
