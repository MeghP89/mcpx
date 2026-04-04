pub mod stdio;
pub mod proxy;

#[cfg(test)]
mod tests {
    #[test]
    fn exports_are_accessible() {
        let _ = super::stdio::read_client_stdin as fn() -> tokio::sync::mpsc::Receiver<String>;
        let _ = super::proxy::ProxyState::new as fn() -> super::proxy::ProxyState;
    }
}
