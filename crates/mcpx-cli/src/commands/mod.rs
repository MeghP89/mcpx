pub mod baselines;
pub mod diff;
pub mod events;
pub mod run;

#[cfg(test)]
mod tests {
    use anyhow::Result;

    #[test]
    fn module_exports_are_accessible() {
        let _ = super::baselines::list as fn() -> Result<()>;
        let _ = super::diff::execute as fn(&str) -> Result<()>;
        let _ = super::events::list as fn(&str, usize) -> Result<()>;
        let _ = super::run::execute;
    }
}
