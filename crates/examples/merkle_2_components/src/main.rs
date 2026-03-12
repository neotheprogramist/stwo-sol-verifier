pub mod mixer;
pub mod utils;
pub mod scheduler;
pub mod computing;
pub mod trace_gen;
pub mod gnark_json_gen;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🧑‍🔬 Merkle 2 Components Example");
    Ok(())
}