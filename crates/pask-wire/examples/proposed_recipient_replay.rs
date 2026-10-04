// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Wilder Management Inc. (d/b/a Wilder Robotics)
//! Local example, not an installed/registry CLI or new release command.
//! Reads only explicitly selected files; no remote fetch or embedded path lookup.
//! Exit 0 means a report was produced, NOT that evidence is acceptable.

// Output failures are ordinary I/O errors, including failures during help and
// diagnostics. The caller still needs to observe the process exit code when a
// diagnostic cannot be delivered. These helpers do not catch arbitrary panics.
fn write_all_and_flush<W: std::io::Write>(writer: &mut W, bytes: &[u8]) -> std::io::Result<()> {
    writer.write_all(bytes)?;
    writer.flush()
}

#[cfg(feature = "alloc")]
fn diagnostic_exit_code<W: std::io::Write>(writer: &mut W, message: &str) -> i32 {
    // Reporting an existing error must not panic or turn the failure into
    // success merely because stderr is unwritable. Preserve the original text.
    let _ = writeln!(writer, "replay_error: {message}").and_then(|()| writer.flush());
    2
}

#[cfg(not(feature = "alloc"))]
fn main() {
    let mut output = std::io::stderr().lock();
    let _ = write_all_and_flush(
        &mut output,
        b"This local example requires --features alloc.\n",
    );
    std::process::exit(2);
}

#[cfg(feature = "alloc")]
mod app {
    use pask_wire::proposed_replay::{
        MAX_DOCUMENT_BYTES, ReplayMode, inspect_replay_document, replay_key_from_hex,
    };
    use std::{
        fs::{File, OpenOptions},
        io::{self, Read, Write},
        path::PathBuf,
    };

    const HELP: &str = "Local proposed recipient replay (not full PSER acceptance)\n\
Usage: proposed_recipient_replay --mode single|chain --input replay.json --key public-key.hex [--output report.json]\n\
The key file is an explicitly supplied 64-lowercase-hex Ed25519 public key.\n\
Output files are created exclusively; existing files are never overwritten.\n\
Exit 0: report produced (may contain failures). Exit 2: input/usage/I/O failure.\n\
Single mode requires one entry and never checks predecessor contiguity.\n\
Chain mode checks presented links from genesis using one key for all entries.\n\
Neither mode establishes latest history, hardware, identity, or application acceptance.\n";

    pub struct Args {
        pub mode: ReplayMode,
        pub input: PathBuf,
        pub key: PathBuf,
        pub output: Option<PathBuf>,
    }
    pub fn parse(args: &[String]) -> Result<Option<Args>, &'static str> {
        if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
            return Ok(None);
        }
        let (mut mode, mut input, mut key, mut output) = (None, None, None, None);
        let mut i = 0;
        while i < args.len() {
            let value = args.get(i + 1).ok_or("missing option value")?;
            match args[i].as_str() {
                "--mode" if mode.is_none() => {
                    mode = Some(match value.as_str() {
                        "single" => ReplayMode::Single,
                        "chain" => ReplayMode::Chain,
                        _ => return Err("mode must be single or chain"),
                    })
                }
                "--input" if input.is_none() => input = Some(PathBuf::from(value)),
                "--key" if key.is_none() => key = Some(PathBuf::from(value)),
                "--output" if output.is_none() => output = Some(PathBuf::from(value)),
                _ => return Err("unknown or duplicate option"),
            }
            i += 2;
        }
        Ok(Some(Args {
            mode: mode.ok_or("explicit --mode required")?,
            input: input.ok_or("--input required")?,
            key: key.ok_or("--key required")?,
            output,
        }))
    }
    fn read_file(path: &PathBuf, maximum: usize) -> Result<Vec<u8>, &'static str> {
        // Reject a non-regular path before opening it as well as after opening.
        // Caller-selected filesystem access is not a symlink or race sandbox.
        let selected = std::fs::metadata(path).map_err(|_| "cannot inspect selected input path")?;
        if !selected.is_file() {
            return Err("input must be a regular file");
        }
        let file = File::open(path).map_err(|_| "cannot open explicit input file")?;
        let meta = file
            .metadata()
            .map_err(|_| "cannot inspect explicit input file")?;
        if !meta.is_file() {
            return Err("input must be a regular file");
        }
        if meta.len() > maximum as u64 {
            return Err("input exceeds byte limit");
        }
        let mut bytes = Vec::new();
        file.take((maximum as u64) + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "input read failed")?;
        if bytes.len() > maximum {
            return Err("input grew beyond byte limit");
        }
        Ok(bytes)
    }
    pub(super) fn write_help<W: Write>(output: &mut W) -> Result<(), &'static str> {
        super::write_all_and_flush(output, HELP.as_bytes()).map_err(|_| "help output failed")
    }

    pub fn run(args: &[String]) -> Result<(), &'static str> {
        let Some(args) = parse(args)? else {
            return write_help(&mut io::stdout().lock());
        };
        let key_file = read_file(&args.key, 256)?;
        let key_text = std::str::from_utf8(&key_file).map_err(|_| "key file is not UTF-8 hex")?;
        let key_text = key_text.trim_matches([' ', '\t', '\r', '\n']);
        let key = replay_key_from_hex(key_text).map_err(|e| e.code())?;
        let input = read_file(&args.input, MAX_DOCUMENT_BYTES)?;
        let report = inspect_replay_document(&input, &key, args.mode).map_err(|e| e.code())?;
        let mut encoded =
            serde_json::to_vec_pretty(&report).map_err(|_| "report encoding failed")?;
        encoded.push(b'\n');
        if let Some(path) = &args.output {
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map_err(|_| "output must be a new writable file")?;
            // A write failure may leave a partial newly created file. Return
            // nonzero and do not label it a completed report; never overwrite.
            output
                .write_all(&encoded)
                .and_then(|()| output.flush())
                .map_err(|_| "report write failed; output may be partial")?;
        } else {
            let mut output = io::stdout().lock();
            output
                .write_all(&encoded)
                .and_then(|()| output.flush())
                .map_err(|_| "report output failed")?;
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        fn argv(a: &[&str]) -> Vec<String> {
            a.iter().map(|s| (*s).to_owned()).collect()
        }
        #[test]
        fn explicit_mode_and_key_are_mandatory() {
            assert!(parse(&argv(&["--input", "x", "--key", "y"])).is_err());
            assert!(parse(&argv(&["--mode", "single", "--input", "x"])).is_err());
        }
        #[test]
        fn duplicate_or_unknown_option_rejects() {
            assert!(
                parse(&argv(&[
                    "--mode", "single", "--mode", "chain", "--input", "x", "--key", "y"
                ]))
                .is_err()
            );
            assert!(parse(&argv(&["--url", "https://invalid"])).is_err());
        }
        #[test]
        fn chain_mode_is_explicit_not_inferred_from_file_name() {
            let args = parse(&argv(&[
                "--mode",
                "chain",
                "--input",
                "single.json",
                "--key",
                "key.hex",
            ]))
            .unwrap()
            .unwrap();
            assert_eq!(args.mode, ReplayMode::Chain);
        }
        #[test]
        fn optional_report_path_does_not_change_mode() {
            let args = parse(&argv(&[
                "--mode", "single", "--input", "x", "--key", "y", "--output", "z",
            ]))
            .unwrap()
            .unwrap();
            assert_eq!(args.mode, ReplayMode::Single);
            assert_eq!(args.output, Some(PathBuf::from("z")));
        }
        #[test]
        fn help_alone_is_not_an_execution_request() {
            assert!(parse(&argv(&["--help"])).unwrap().is_none());
        }
    }
}

#[cfg(feature = "alloc")]
fn main() {
    if let Err(message) = app::run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        let mut output = std::io::stderr().lock();
        std::process::exit(diagnostic_exit_code(&mut output, message));
    }
}

#[cfg(all(test, feature = "alloc"))]
mod output_tests {
    use std::io::{self, Write};

    use super::{app, diagnostic_exit_code, write_all_and_flush};

    #[derive(Default)]
    struct Sink {
        bytes: Vec<u8>,
        max_write: Option<usize>,
        fail_write: bool,
        fail_flush: bool,
        flushes: usize,
    }

    impl Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.fail_write {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "injected write failure",
                ));
            }
            let count = bytes.len().min(self.max_write.unwrap_or(bytes.len()));
            self.bytes.extend_from_slice(&bytes[..count]);
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            if self.fail_flush {
                return Err(io::Error::other("injected flush failure"));
            }
            Ok(())
        }
    }

    #[test]
    fn help_bytes_are_complete_and_flushed() {
        let mut sink = Sink::default();
        assert_eq!(app::write_help(&mut sink), Ok(()));
        let mut expected = Vec::new();
        assert_eq!(app::write_help(&mut expected), Ok(()));
        assert_eq!(sink.bytes, expected);
        assert!(sink.bytes.starts_with(b"Local proposed recipient replay"));
        assert!(sink.bytes.ends_with(b"application acceptance.\n"));
        assert_eq!(sink.flushes, 1);
    }

    #[test]
    fn help_short_writes_still_produce_identical_bytes() {
        let mut sink = Sink {
            max_write: Some(3),
            ..Sink::default()
        };
        let mut expected = Vec::new();
        app::write_help(&mut expected).unwrap();
        assert_eq!(app::write_help(&mut sink), Ok(()));
        assert_eq!(sink.bytes, expected);
        assert_eq!(sink.flushes, 1);
    }

    #[test]
    fn help_write_failure_is_a_result_not_a_panic() {
        let mut sink = Sink {
            fail_write: true,
            ..Sink::default()
        };
        assert_eq!(app::write_help(&mut sink), Err("help output failed"));
        assert!(sink.bytes.is_empty());
        assert_eq!(sink.flushes, 0);
    }

    #[test]
    fn help_flush_failure_is_a_result_not_success() {
        let mut sink = Sink {
            fail_flush: true,
            ..Sink::default()
        };
        assert_eq!(app::write_help(&mut sink), Err("help output failed"));
        assert!(!sink.bytes.is_empty());
        assert_eq!(sink.flushes, 1);
    }

    #[test]
    fn help_zero_progress_is_an_io_error() {
        let mut sink = Sink {
            max_write: Some(0),
            ..Sink::default()
        };
        assert_eq!(app::write_help(&mut sink), Err("help output failed"));
        assert!(sink.bytes.is_empty());
        assert_eq!(sink.flushes, 0);
    }

    #[test]
    fn diagnostic_preserves_exact_text_and_exit_two() {
        let mut sink = Sink::default();
        assert_eq!(diagnostic_exit_code(&mut sink, "bad option"), 2);
        assert_eq!(sink.bytes, b"replay_error: bad option\n");
        assert_eq!(sink.flushes, 1);
    }

    #[test]
    fn diagnostic_short_writes_keep_text_and_exit_two() {
        let mut sink = Sink {
            max_write: Some(2),
            ..Sink::default()
        };
        assert_eq!(diagnostic_exit_code(&mut sink, "bad option"), 2);
        assert_eq!(sink.bytes, b"replay_error: bad option\n");
        assert_eq!(sink.flushes, 1);
    }

    #[test]
    fn diagnostic_write_failure_keeps_exit_two() {
        let mut sink = Sink {
            fail_write: true,
            ..Sink::default()
        };
        assert_eq!(diagnostic_exit_code(&mut sink, "bad option"), 2);
        assert!(sink.bytes.is_empty());
        assert_eq!(sink.flushes, 0);
    }

    #[test]
    fn diagnostic_flush_failure_keeps_exit_two() {
        let mut sink = Sink {
            fail_flush: true,
            ..Sink::default()
        };
        assert_eq!(diagnostic_exit_code(&mut sink, "bad option"), 2);
        assert_eq!(sink.bytes, b"replay_error: bad option\n");
        assert_eq!(sink.flushes, 1);
    }

    #[test]
    fn diagnostic_zero_progress_keeps_exit_two() {
        let mut sink = Sink {
            max_write: Some(0),
            ..Sink::default()
        };
        assert_eq!(diagnostic_exit_code(&mut sink, "bad option"), 2);
        assert!(sink.bytes.is_empty());
        assert_eq!(sink.flushes, 0);
    }

    #[test]
    fn failed_help_and_failed_diagnostic_still_select_exit_two() {
        let mut output = Sink {
            fail_write: true,
            ..Sink::default()
        };
        let message = app::write_help(&mut output).unwrap_err();
        let mut diagnostics = Sink {
            fail_flush: true,
            ..Sink::default()
        };
        assert_eq!(diagnostic_exit_code(&mut diagnostics, message), 2);
        assert_eq!(diagnostics.bytes, b"replay_error: help output failed\n");
        // The no-feature path uses this same fallible byte writer, without a
        // feature-dependent verifier or a new diagnostic prefix.
        assert!(write_all_and_flush(&mut output, b"feature required\n").is_err());
    }
}
