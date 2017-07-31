#[macro_use]
extern crate derive_new;

#[macro_use]
extern crate error_chain;
extern crate libresolv_sys;

#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate structopt;

#[macro_use]
extern crate structopt_derive;

use libresolv_sys::MAXHOSTNAMELEN;
use std::collections::HashMap;
use std::ffi::CStr;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::raw::{c_char, c_float, c_int};
use std::process;
use std::ptr;
use std::slice;
use structopt::StructOpt;

extern {
    #[link(name="lsf")]
    fn ls_load(resreq: *mut c_char, numhosts: *mut c_int, options: c_int, fromhost: *mut c_char) -> *mut hostLoad; 
}

#[repr(C)]
pub struct hostLoad {
    host_name: [c_char; MAXHOSTNAMELEN as usize],
    status: *mut c_int,
    li: *mut c_float,
}

mod common {
    #[derive(Serialize, Deserialize, Clone, Debug)]
    #[serde(rename_all = "camelCase")]
    pub struct StorageInfo {
        used: u64,
        total: u64,
    }

    #[derive(Serialize, Deserialize, Clone, Debug, new)]
    #[serde(rename_all = "camelCase")]
    pub struct StatusStorageInfo {
        pub name: String,
        pub status: i32,

        #[serde(skip_serializing_if = "Option::is_none")]
        pub storage: Option<StorageInfo>,

        #[serde(skip_serializing_if = "Option::is_none")]        
        pub critical_group_name: Option<String>,

        #[serde(skip_serializing_if = "Option::is_none")]        
        pub remarks: Option<String>,
    }
}

use common::StatusStorageInfo;

// LSF status flags
const LIM_OK: i32 = 0x00000000;
const LIM_UNAVAIL: i32 = 0x00010000;
const LIM_LOCKEDU: i32 = 0x00020000;
const LIM_LOCKEDW: i32 = 0x00040000;
const LIM_BUSY: i32 = 0x00080000;
const LIM_RESDOWN: i32 = 0x00100000;
const LIM_UNLICENSED: i32 = 0x00200000;
const LIM_SBDDOWN: i32 = 0x00400000;
const LIM_LOCKEDM: i32 = 0x00800000;
const LIM_PEMDOWN: i32 = 0x01000000;
const LIM_EXPIRED: i32 = 0x02000000;
const LIM_RLAUP: i32 = 0x04000000;

#[allow(overflowing_literals)]
const LIM_LOCKEDU_RMS: i32 = 0x80000000;
// const LIM_OK_MASK: i32 = 0x02bf0000;
const ALL_CLUSTERS: i32 = 0x80;

// status values
const PASSED: i32 = 0;
// const ALERT: i32 = 1;
const FAILED: i32 = 2;

// exit code
const NORMAL: i32 = 0;
// const INVALID_ARGS: i32 = 1;
const ERROR: i32 = 127;

fn to_status_str(status: i32) -> &'static str {
    match status {
        LIM_OK => "LIM_OK",
        LIM_UNAVAIL => "LIM_UNAVAIL",
        LIM_LOCKEDU => "LIM_LOCKEDU",
        LIM_LOCKEDW => "LIM_LOCKEDW",
        LIM_BUSY => "LIM_BUSY",
        LIM_RESDOWN => "LIM_RESDOWN",
        LIM_UNLICENSED => "LIM_UNLICENSED",
        LIM_SBDDOWN => "LIM_SBDDOWN",
        LIM_LOCKEDM => "LIM_LOCKEDM",
        LIM_PEMDOWN => "LIM_PEMDOWN",
        LIM_EXPIRED => "LIM_EXPIRED",
        LIM_RLAUP => "LIM_RLAUP",
        LIM_LOCKEDU_RMS => "LIM_LOCKEDU_RMS",
        _ => "UNKNOWN",
    }
}

mod errors {
    error_chain! {}
}

use errors::*;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Config {
    prefix: String,
    name_mapping: HashMap<String, String>,
    critical_group_name: String,
}


#[derive(StructOpt, Debug)]
#[structopt(name = "LSF Agent", about = "Simple LSF program to poll for LSF host status.")]
struct MainArgMap {
    #[structopt(short = "c", long = "config", help = "Configuration file path")]
    config_path: String,
}

fn run() -> Result<i32> {
    let main_arg_map = MainArgMap::from_args();

    let config_content = {
        let mut config_file = File::open(&main_arg_map.config_path)
            .chain_err(|| format!("Unable to open config file at {}", main_arg_map.config_path))?;

        let mut buf = String::new();
        let _ = config_file.read_to_string(&mut buf)
            .chain_err(|| "Unable to read config file into string")?;

        buf
    };

    let config: Config = serde_json::from_str(&config_content)
        .chain_err(|| "Unable to parse config content into structure!")?;

    let mut numhosts: c_int = 0;
    let host_load_vals = unsafe { ls_load(ptr::null_mut(), &mut numhosts, ALL_CLUSTERS, ptr::null_mut()) };
    let host_load_vals = unsafe { slice::from_raw_parts(host_load_vals, numhosts as usize) };

    let numhosts = numhosts;

    let status_storage_infos =
        if numhosts > 0 {
            host_load_vals.into_iter()
                .map(|host_load| {
                    let status = unsafe { *host_load.status };
                    let status_str = to_status_str(status);

                    let host_name_raw = unsafe { CStr::from_ptr(host_load.host_name.as_ptr()) };
                    let host_name = host_name_raw.to_str();

                    let conv_status = if status == LIM_OK { PASSED } else { FAILED };
                    let critical_group_name = config.critical_group_name.clone();

                    // very unlikely to be unable to interpret cstr as str here
                    match host_name {
                        Ok(host_name) => {
                            let mapped_host_name = match config.name_mapping.get(host_name) {
                                Some(mapped_host_name) => mapped_host_name,
                                None => host_name,
                            };

                            StatusStorageInfo::new(
                                format!("{}{}", config.prefix, mapped_host_name),
                                conv_status,
                                None,
                                Some(critical_group_name),
                                Some(format!("Status code: {} ({})", status, status_str)))
                        },

                        Err(_) => StatusStorageInfo::new(
                            format!("{}{:?}", config.prefix, host_name_raw),
                            conv_status,
                            None,
                            Some(critical_group_name),
                            Some(format!("Status code: {} ({})", status, status_str))),
                    }
                })
                .collect()
        } else {
            vec![StatusStorageInfo::new(
                format!("{}*", config.prefix),
                FAILED,
                None,
                Some(config.critical_group_name.clone()),
                Some("Unable to connect any of the LSF nodes".to_owned()))]
        };

    let all_passed = status_storage_infos.iter()
        .all(|status_storage_info| status_storage_info.status == PASSED);

    let exit_code = match all_passed {
        true => NORMAL,
        _ => ERROR,
    };

    // status_storage_infos
    let status_storage_infos_str = serde_json::to_string(&status_storage_infos)
        .chain_err(|| "Unable to serialize list of status storage into string!")?;

    println!("{}", status_storage_infos_str);

    Ok(exit_code)
}

fn main() {
    match run() {
        Ok(exit_code) => process::exit(exit_code),
        Err(ref e) => {
            let stderr = &mut io::stderr();

            writeln!(stderr, "Error: {}", e)
                .expect("Unable to write error into stderr!");

            for e in e.iter().skip(1) {
                writeln!(stderr, "- Caused by: {}", e)
                    .expect("Unable to write error causes into stderr!");
            }

            process::exit(1);
        },
    }
}
