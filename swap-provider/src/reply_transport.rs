//! Request-local replies keep session traffic separate from root-key encrypted DMs.

use pubky_transport::Transport;
use serde::Serialize;
use std::{
    ops::Deref,
    sync::{Arc, Mutex},
};
use tokio::sync::oneshot;

pub(crate) struct ReplyTransport {
    inner: Arc<Transport>,
    reply: Option<Mutex<Option<oneshot::Sender<Vec<u8>>>>>,
    account: Option<String>,
    scope: Option<String>,
}

impl ReplyTransport {
    pub(crate) fn account(&self) -> Option<&str> {
        self.account.as_deref()
    }

    pub(crate) fn authorization(&self) -> Option<(&str, &str)> {
        self.account.as_deref().zip(self.scope.as_deref())
    }

    pub(crate) fn direct(inner: Transport) -> Self {
        Self {
            inner: Arc::new(inner),
            reply: None,
            account: None,
            scope: None,
        }
    }

    #[cfg(feature = "iroh")]
    pub(crate) fn session(
        &self,
        account: String,
        scope: String,
        reply: oneshot::Sender<Vec<u8>>,
    ) -> Self {
        Self {
            inner: self.inner.clone(),
            reply: Some(Mutex::new(Some(reply))),
            account: Some(account),
            scope: Some(scope),
        }
    }

    pub(crate) async fn send<T: Serialize>(
        &self,
        peer: &str,
        message: &T,
    ) -> pubky_transport::Result<()> {
        let Some(reply) = &self.reply else {
            return self.inner.send(peer, message).await;
        };
        let bytes = serde_json::to_vec(message)?;
        if let Some(sender) = reply
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
        {
            let _ = sender.send(bytes);
        }
        // Session clients poll durable status; background updates do not become root-key DMs.
        Ok(())
    }
}

impl Deref for ReplyTransport {
    type Target = Transport;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
