use std::process::Command;
use std::str::FromStr;

fn main() {
    // Run cargo bloat command
    let output = Command::new("sh")
        .arg("-c")
        .arg("cd tests && cargo bloat --release -n 0 | grep f_miniscript")
        .output()
        .expect("Failed to execute cargo bloat");

    let output_str = String::from_utf8_lossy(&output.stdout);
    
    // Parse and calculate total size
    let mut total_bytes : u64 = 0;
    
    for line in output_str.lines() {
        if line.contains("f_miniscript") {
            // Extract size from lines like "0.2%   3.0%   9.0KiB  f_miniscript"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                if let Some(size_str) = parts.get(2) {
                    if size_str.ends_with("KiB") {

                        if let Ok(size) = f64::from_str(&size_str[..size_str.len()-3]) {
                            total_bytes += (size * 1024.0) as u64;
                        }
                    } else if size_str.ends_with("B") {
                        
                        if let Ok(size) = u64::from_str(&size_str[..size_str.len()-1]) {
                            total_bytes += size;
                        }
                    }
                }
            }
        }
    }
    
    // Convert to KB
    let total_kb = total_bytes as f64 / 1024.0;
    
    println!("{}", output_str);
    println!("");
    println!("Total miniscript implementation size breakdown:");
    println!("==============================================");
    println!("Total miniscript code size: {:.1} KB", total_kb);
} 