pub mod patterns;
pub mod structural;

#[cfg(test)]
mod tests {
    #[test]
    fn exports_are_accessible() {
        let _ = super::patterns::scan_injections as fn(&str) -> Vec<String>;
        let _ = super::structural::analyze
            as fn(&str, &str, &str, f64) -> super::structural::PoisoningAnalysis;
        let _ = super::structural::analyze_parameter_name
            as fn(&str, &str) -> super::structural::FieldPoisoningAnalysis;
        let _ = super::structural::analyze_parameter_description
            as fn(&str, &str, &str) -> super::structural::FieldPoisoningAnalysis;
    }
}
