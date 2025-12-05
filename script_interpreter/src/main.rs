
use anyhow::{bail, Result};
use hex::{decode as hex_decode, encode as hex_encode};
use sha2::{Digest, Sha256};
use ripemd::Ripemd160;
use std::collections::HashMap;
use std::io::{self, Write};

type Stack = Vec<Vec<u8>>;

macro_rules! lazy_static {
    ($init:expr) => {
        std::sync::OnceLock::from($init)
    };
}

static OPCODE_MAP: std::sync::OnceLock<HashMap<u8, &'static str>> = std::sync::OnceLock::new();
static REVERSE_OPCODE_MAP: std::sync::OnceLock<HashMap<&'static str, u8>> = std::sync::OnceLock::new();

fn init_opcodes() {
    let mut op = HashMap::new();
    op.insert(0x00, "OP_0");
    for i in 1..=16 {
        op.insert(0x50 + i, match i {
            1 => "OP_1",
            2 => "OP_2",
            3 => "OP_3",
            4 => "OP_4",
            5 => "OP_5",
            6 => "OP_6",
            7 => "OP_7",
            8 => "OP_8",
            9 => "OP_9",
            10 => "OP_10",
            11 => "OP_11",
            12 => "OP_12",
            13 => "OP_13",
            14 => "OP_14",
            15 => "OP_15",
            16 => "OP_16",
            _ => unreachable!(),
        });
    }
    op.insert(0x76, "OP_DUP");
    op.insert(0x87, "OP_EQUAL");
    op.insert(0x88, "OP_EQUALVERIFY");
    op.insert(0xac, "OP_CHECKSIG");
    op.insert(0xae, "OP_CHECKMULTISIG");
    op.insert(0xa9, "OP_HASH160");
    op.insert(0x6a, "OP_RETURN");

    let mut rev = HashMap::new();
    for (&byte, &name) in &op {
        rev.insert(name, byte);
    }
    rev.insert("OP_FALSE", 0x00);
    rev.insert("OP_TRUE", 0x51);

    let _ = OPCODE_MAP.set(op);
    let _ = REVERSE_OPCODE_MAP.set(rev);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScriptType {
    P2PK,
    P2PKH,
    
    P2SH,
    P2MS,
    Return,
    Unknown,
}

#[derive(Clone)]
struct Script {
    hex: String,
    asm: Vec<String>,
    script_type: ScriptType,
}

fn hash160(data: &[u8]) -> Vec<u8> {
    let sha = Sha256::digest(data);
    let mut ripemd = Ripemd160::new();
    ripemd.update(sha);
    ripemd.finalize().to_vec()
}

impl Script {
    fn new(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.contains(' ') || trimmed.contains("OP_") {
            Self::from_asm(trimmed)
        } else {
            Self::from_hex(trimmed)
        }
    }

    fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex_decode(hex_str)?;
        let asm = Self::bytes_to_asm(&bytes);
        let script_type = Self::detect_type(&asm);
        Ok(Script {
            hex: hex_str.to_ascii_lowercase(),
            asm,
            script_type,
        })
    }

    fn from_asm(asm_str: &str) -> Result<Self> {
        let asm: Vec<String> = asm_str.split_whitespace().map(|s| s.to_string()).collect();
        let bytes = Self::asm_to_bytes(&asm)?;
        let hex = hex_encode(&bytes);
        let script_type = Self::detect_type(&asm);
        Ok(Script { hex, asm, script_type })
    }

    fn bytes_to_asm(bytes: &[u8]) -> Vec<String> {
        let mut asm = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            let op = bytes[i];
            i += 1;

            if op >= 0x01 && op <= 0x4b {
                let len = op as usize;
                if i + len > bytes.len() { break; }
                let data = &bytes[i..i + len];
                asm.push(hex_encode(data));
                i += len;
            } else if let Some(&name) = OPCODE_MAP.get().and_then(|m| m.get(&op)) {
                asm.push(name.to_string());
            } else {
                asm.push(format!("{:02x}", op));
            }
        }
        asm
    }

    fn asm_to_bytes(asm: &[String]) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        for part in asm {
            if let Some(&code) = REVERSE_OPCODE_MAP.get().and_then(|m| m.get(part.as_str())) {
                bytes.push(code);
            } else if let Ok(n) = part.strip_prefix("OP_").unwrap_or("").parse::<u8>() {
                if n <= 16 {
                    bytes.push(0x50 + n);
                } else {
                    bail!("Invalid OP_n");
                }
            } else {
                // Raw data push
                let data = hex_decode(part)?;
                let len = data.len();
                if len < 0x4c {
                    bytes.push(len as u8);
                } else if len <= 0xff {
                    bytes.push(0x4c);
                    bytes.push(len as u8);
                } else {
                    bail!("Data too large");
                }
                bytes.extend_from_slice(&data);
            }
        }
        Ok(bytes)
    }

    fn detect_type(asm: &[String]) -> ScriptType {


        let op_ch="OP_CHECKSIG".to_string();
        let op_dup="OP_DUP".to_string();
        let op_has="OP_HASH160".to_string();
        let op_eq="OP_EQUALVERIFY".to_string();
        let op_equ="OP_EQUAL".to_string();
        let op_ren="OP_RETURN".to_string();

       match asm {
            [_, op_ch] => ScriptType::P2PK,
            [op_dup, op_has, _, op_eq, op_ch] => ScriptType::P2PKH,
            [op_has, _, op_equ] => ScriptType::P2SH,
            _ if asm.last().map_or(false, |s| s == "OP_CHECKMULTISIG") => ScriptType::P2MS,
            [op_ren, ..] => ScriptType::Return,
            _ => ScriptType::Unknown,
        }
    }

    fn run(scripts: &[Script], debug: bool) -> Result<Stack> {
        let mut full_script: Vec<String> = scripts.iter().flat_map(|s| s.asm.clone()).collect();
        let mut stack: Stack = Vec::new();

        while let Some(op) = full_script.first().cloned() {
            full_script.remove(0);

            let executed = if let Some(&code) = REVERSE_OPCODE_MAP.get().and_then(|m| m.get(op.as_str())) {
                match code {
                    0x76 => { // OP_DUP
                        let top = stack.last().ok_or_else(|| anyhow::anyhow!("OP_DUP on empty stack"))?.clone();
                        stack.push(top);
                        true
                    }
                    0xa9 => { // OP_HASH160
                        let elem = stack.pop().ok_or_else(|| anyhow::anyhow!("OP_HASH160 on empty stack"))?;
                        stack.push(hash160(&elem));
                        true
                    }
                    0x87 => { // OP_EQUAL
                        let b = stack.pop().unwrap();
                        let a = stack.pop().unwrap();
                        stack.push(if a == b { vec![1u8] } else { vec![] });
                        true
                    }
                    0x88 => { // OP_EQUALVERIFY
                        let b = stack.pop().unwrap();
                        let a = stack.pop().unwrap();
                        if a != b {
                            bail!("OP_EQUALVERIFY failed");
                        }
                        true
                    }
                    0xac => { // OP_CHECKSIG – fake success
                        stack.pop();
                        stack.pop();
                        stack.push(vec![1u8]);
                        true
                    }
                    0xae => { // OP_CHECKMULTISIG – fake + off-by-one bug
                        let n = stack.pop().unwrap()[0] as usize - 0x50;
                        for _ in 0..n { stack.pop(); }
                        let m = stack.pop().unwrap()[0] as usize - 0x50;
                        for _ in 0..m { stack.pop(); }
                        stack.pop(); // extra pop – Bitcoin bug emulation
                        stack.push(vec![1u8]);
                        true
                    }
                    0x6a => bail!("OP_RETURN makes script invalid"),
                    _ => false,
                }
            } else {
                false
            };

            if !executed {
                // Must be pushed data
                let data = hex_decode(&op)?;
                stack.push(data);
            }

            if debug {
                Self::debug_print(&full_script, &stack);
                let mut dummy = String::new();
                io::stdin().read_line(&mut dummy).ok();
            }
        }

        Ok(stack)
    }

    fn debug_print(remaining: &[String], stack: &Stack) {
        print!("\x1B[2J\x1B[H"); // clear screen
        println!("Remaining script: {remaining:?}\n");
        println!("Stack (top → bottom):");
        if stack.is_empty() {
            println!("  <empty>");
        } else {
            for item in stack.iter().rev() {
                println!("  {}", hex_encode(item));
            }
        }
        println!("\nPress Enter for next step...");
        io::stdout().flush().unwrap();
    }

    fn validate(stack: &Stack) -> bool {
        !stack.is_empty() && !stack.last().unwrap().is_empty()
    }
}

fn main() -> Result<()> {
    init_opcodes();

    println!("Bitcoin Script Interpreter (Rust)\n");

    print!("Locking script (hex or asm): ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let locking = Script::new(&input)?;

    println!("Type: {:?}\n", locking.script_type);

    print!("Unlocking script (hex or asm): ");
    io::stdout().flush()?;
    input.clear();
    io::stdin().read_line(&mut input)?;
    let unlocking = Script::new(&input)?;

    println!("\n=== Scripts ===");
    println!("Locking : {}", locking.asm.join(" "));
    println!("Unlocking: {}", unlocking.asm.join(" "));
    println!("\nPress Enter to start execution...");
    io::stdin().read_line(&mut String::new())?;

    let final_stack = if locking.script_type == ScriptType::P2SH {
        // Very simple P2SH handling – assumes redeem script is last push in unlocking scriptSig
        let redeem_hex = unlocking.asm.last().unwrap();
        let redeem_script = Script::from_hex(redeem_hex)?;
        Script::run(&[unlocking.clone(), redeem_script], true)?
    } else {
        Script::run(&[unlocking.clone(), locking.clone()], true)?
    };

    println!("\n=== Final stack ===");
    for item in final_stack.iter().rev() {
        println!("  {}", hex_encode(item));
    }

    if Script::validate(&final_stack) {
        println!("\nVALID – Transaction would be accepted");
    } else {
        println!("\nINVALID – Transaction rejected");
    }

    Ok(())
}