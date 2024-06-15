use clap::{Args, Parser, Subcommand};
use std::fs::DirEntry;
use std::path::PathBuf;
use std::process;

mod lib;

#[derive(Parser)]
#[clap(version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    commands: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypts the file or folder.
    Encrypt(EncryptArgs),
    /// Decrypts the file.
    Decrypt(EncryptArgs),
}

#[derive(Args)]
struct EncryptArgs {
    file_path: PathBuf,
    password: String,
}

fn main() {
    let cli = Cli::parse();

    match &cli.commands {
        Commands::Encrypt(args) => {
            if let Err(e) = validate_args(args) {
                exit_with_error(&e);
            };
            println!("Encrypting with password {}", args.password);
            if let Err(e) = lib::file_encryptor::encrypt_file(&args.file_path, &args.password) {
                exit_with_error(&e.to_string());
            }
        }
        Commands::Decrypt(args) => {
            println!("Decrypting with password {}", args.password);
            if let Err(e) = lib::file_encryptor::decrypt_file(&args.file_path, &args.password) {
                exit_with_error(&e.to_string());
            }
        }
    }
}

fn validate_args(args: &EncryptArgs) -> Result<(), String> {
    if args.file_path.exists() {
        Ok(())
    } else {
        Err(String::from("File does not exist."))
    }
}

fn exit_with_error(error: &str) {
    eprintln!("Application error: {}", error);
    process::exit(1);
}
