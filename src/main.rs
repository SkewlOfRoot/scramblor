use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use clap::{Args, Parser, Subcommand};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::process;

mod aes_encryptor;
mod file_encryptor;

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

            let password = hash_string_to_32_chars(&args.password);
            if let Err(e) = file_encryptor::encrypt_file(&args.file_path, &password) {
                exit_with_error(&e.to_string());
            }
        }
        Commands::Decrypt(args) => {
            let password = hash_string_to_32_chars(&args.password);
            if let Err(e) = file_encryptor::decrypt_file(&args.file_path, &password) {
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

fn hash_string_to_32_chars(input: &str) -> String {
    // Hash input string.
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();

    // Convert to base64.
    let mut str_buffer = String::new();
    URL_SAFE_NO_PAD.encode_string(result, &mut str_buffer);
    str_buffer.chars().take(32).collect()
}

fn exit_with_error(error: &str) {
    eprintln!("Application error: {}", error);
    process::exit(1);
}
