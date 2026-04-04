pub mod structural;
pub mod patterns;

#[cfg(test)]
mod tests {
    #[test]
    fn exports_are_accessible() {
        let _ = super::patterns::scan_injections as fn(&str) -> Vec<String>;
        let _ = super::structural::analyze
            as fn(&str, &str, &str, f64) -> super::structural::PoisoningAnalysis;
    }
}
