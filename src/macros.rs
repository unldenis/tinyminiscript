#[macro_export]
macro_rules! properties_from_str {
    ($s:expr) => {{
        let mut props = Vec::new();
        for c in $s.chars() {
            match c {
                'z' | 'Z' => props.push(Property::Z),
                'o' | 'O' => props.push(Property::O),
                'n' | 'N' => props.push(Property::N),
                'd' | 'D' => props.push(Property::D),
                'u' | 'U' => props.push(Property::U),
                _ => continue,
            }
        }
        props
    }};
}
