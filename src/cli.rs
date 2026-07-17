use std::env;
use std::ffi::{OsStr, OsString};
use std::path::Path;

#[derive(Clone, Copy)]
pub(crate) enum ConcealOption {
    None,
    Bluesky,
    Reddit,
}

pub(crate) enum ParsedCommand {
    Info,
    Conceal {
        option: ConcealOption,
        image: OsString,
        secret: OsString,
    },
    Recover {
        image: OsString,
    },
}

fn program_name() -> String {
    let argv0 = env::args_os()
        .next()
        .unwrap_or_else(|| OsString::from("jdvrif-rs"));
    Path::new(&argv0)
        .file_name()
        .unwrap_or_else(|| OsStr::new("jdvrif-rs"))
        .to_string_lossy()
        .into_owned()
}

fn usage_message(prog: &str) -> String {
    format!(
        "Usage: {prog} conceal [-b|-r] <cover_image> <secret_file>\n       {prog} recover <cover_image>\n       {prog} --info"
    )
}

pub(crate) fn parse_args(args: &[OsString]) -> Result<ParsedCommand, String> {
    let usage = usage_message(&program_name());
    if args.is_empty() {
        return Err(usage);
    }

    if args.len() == 1 && args[0] == OsStr::new("--info") {
        return Ok(ParsedCommand::Info);
    }

    if args[0] == OsStr::new("conceal") {
        let mut i = 1usize;
        let option = if i < args.len() && args[i] == OsStr::new("-b") {
            i += 1;
            ConcealOption::Bluesky
        } else if i < args.len() && args[i] == OsStr::new("-r") {
            i += 1;
            ConcealOption::Reddit
        } else {
            ConcealOption::None
        };

        if args.len() != i + 2 {
            return Err(usage);
        }

        return Ok(ParsedCommand::Conceal {
            option,
            image: args[i].clone(),
            secret: args[i + 1].clone(),
        });
    }

    if args[0] == OsStr::new("recover") {
        if args.len() != 2 {
            return Err(usage);
        }
        return Ok(ParsedCommand::Recover {
            image: args[1].clone(),
        });
    }

    Err(usage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    fn os(s: &str) -> OsString {
        OsString::from(s)
    }

    #[test]
    fn parse_info_and_recover() {
        match parse_args(&[os("--info")]).unwrap() {
            ParsedCommand::Info => {}
            _ => panic!("expected info"),
        }
        match parse_args(&[os("recover"), os("img.jpg")]).unwrap() {
            ParsedCommand::Recover { image } => assert_eq!(image, os("img.jpg")),
            _ => panic!("expected recover"),
        }
    }

    #[test]
    fn parse_conceal_options() {
        match parse_args(&[os("conceal"), os("a.jpg"), os("s.bin")]).unwrap() {
            ParsedCommand::Conceal {
                option: ConcealOption::None,
                ..
            } => {}
            _ => panic!("default conceal"),
        }
        match parse_args(&[os("conceal"), os("-b"), os("a.jpg"), os("s.bin")]).unwrap() {
            ParsedCommand::Conceal {
                option: ConcealOption::Bluesky,
                ..
            } => {}
            _ => panic!("bluesky"),
        }
        match parse_args(&[os("conceal"), os("-r"), os("a.jpg"), os("s.bin")]).unwrap() {
            ParsedCommand::Conceal {
                option: ConcealOption::Reddit,
                ..
            } => {}
            _ => panic!("reddit"),
        }
    }

    #[test]
    fn parse_rejects_bad_arity() {
        assert!(parse_args(&[]).is_err());
        assert!(parse_args(&[os("conceal")]).is_err());
        assert!(parse_args(&[os("recover")]).is_err());
        assert!(parse_args(&[os("nope")]).is_err());
    }
}
