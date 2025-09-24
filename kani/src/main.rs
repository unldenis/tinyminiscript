fn main() {
    println!("Hello, world!");
}

#[cfg(kani)]
mod verification {
    use super::*;

    #[kani::proof]
    pub fn check_something() {
        assert!(1 == 2)
    }
}
