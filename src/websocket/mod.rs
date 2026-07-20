use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::sync::{Arc, Mutex, MutexGuard};

use std::future::Future;

use bytes::Bytes;
use futures::channel::oneshot::Canceled;
use futures::channel::{mpsc, oneshot};
use futures::future::BoxFuture;
use futures::prelude::*;
use futures::stream::FuturesUnordered;
use reqwest::Method;
use reqwest_websocket::WebSocket;
use tokio::time::Instant;
use tracing::debug;

use crate::configuration::SignalServers;
use crate::prelude::PushService;
use crate::proto::{
    web_socket_message, WebSocketMessage, WebSocketRequestMessage,
    WebSocketResponseMessage,
};
use crate::push_service::{self, ServiceError, SignalServiceResponse};

pub mod account;
#[cfg(feature = "cdsi")]
pub mod directory;
pub mod keys;
pub mod linking;
pub mod profile;
pub mod registration;
mod request;
mod sender;
pub mod stickers;
mod usernames;

pub use request::WebSocketRequestMessageBuilder;

type RequestStreamItem = (
    WebSocketRequestMessage,
    oneshot::Sender<WebSocketResponseMessage>,
);

/// Why the identified websocket worker stopped. Mirrors libsignal-net's
/// close-reason vocabulary (see `rust/net/src/env.rs` close codes) so consumers
/// can classify drops richly instead of treating every close as identical.
#[derive(Debug, Clone)]
pub enum DisconnectReason {
    /// Server closed with 4409 — another device connected with our credentials.
    ConnectedElsewhere,
    /// Server closed with 4401 — this connection's credentials were invalidated.
    ConnectionInvalidated,
    /// Client closed the socket after keepalives went unanswered.
    KeepaliveTimeout,
    /// Server closed with some other code.
    ServerClosed { code: u16, reason: String },
    /// Transport-level end / unexpected error (no clean close frame).
    Transport,
}

impl DisconnectReason {
    fn from_close(code: u16, reason: String) -> Self {
        // 4401/4409 match `rust/net/src/env.rs` CONNECTION_INVALIDATED_CLOSE_CODE /
        // CONNECTED_ELSEWHERE_CLOSE_CODE in the official libsignal-net.
        match code {
            4409 => Self::ConnectedElsewhere,
            4401 => Self::ConnectionInvalidated,
            _ => Self::ServerClosed { code, reason },
        }
    }
}

pub struct SignalRequestStream {
    inner: mpsc::UnboundedReceiver<RequestStreamItem>,
}

impl Stream for SignalRequestStream {
    type Item = RequestStreamItem;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let inner = &mut self.inner;
        futures::pin_mut!(inner);
        Stream::poll_next(inner, cx)
    }
}

#[derive(Debug, Clone)]
pub struct Identified;

#[derive(Debug, Clone)]
pub struct Unidentified;

pub trait WebSocketType: 'static {}

impl WebSocketType for Identified {}

impl WebSocketType for Unidentified {}

/// A dispatching web socket client for the Signal web socket API.
///
/// This structure can be freely cloned, since this acts as a *facade* for multiple entry and exit
/// points.
#[derive(Clone)]
pub struct SignalWebSocket<C: WebSocketType> {
    _type: PhantomData<C>,
    // XXX: at the end of the migration, this should be CDN operations only
    pub(crate) unidentified_push_service: PushService,
    inner: Arc<Mutex<SignalWebSocketInner>>,
    request_sink: mpsc::Sender<(
        WebSocketRequestMessage,
        oneshot::Sender<Result<WebSocketResponseMessage, ServiceError>>,
    )>,
}

struct SignalWebSocketInner {
    stream: Option<SignalRequestStream>,
    /// Filled by the worker on the terminal path; drained once by `MessagePipe`
    /// after the request stream ends, to surface a typed disconnect reason.
    disconnect_reason: Option<oneshot::Receiver<DisconnectReason>>,
}

struct SignalWebSocketProcess {
    /// Whether to enable keep-alive or not (and send a request to this path)
    keep_alive_path: String,

    /// Receives requests from the application, which we forward to Signal.
    requests: mpsc::Receiver<(
        WebSocketRequestMessage,
        oneshot::Sender<Result<WebSocketResponseMessage, ServiceError>>,
    )>,
    /// Signal's requests should go in here, to be delivered to the application.
    request_sink: mpsc::UnboundedSender<RequestStreamItem>,

    outgoing_requests: HashMap<
        u64,
        oneshot::Sender<Result<WebSocketResponseMessage, ServiceError>>,
    >,

    outgoing_keep_alive_set: HashSet<u64>,

    outgoing_responses: FuturesUnordered<
        BoxFuture<'static, Result<WebSocketResponseMessage, Canceled>>,
    >,

    ws: WebSocket,

    /// Sends the typed disconnect reason once, on the terminal path, before the
    /// worker exits (and its `request_sink` drops, ending the request stream).
    disconnect_reason: Option<oneshot::Sender<DisconnectReason>>,
}

impl SignalWebSocketProcess {
    fn set_disconnect_reason(&mut self, reason: DisconnectReason) {
        if let Some(tx) = self.disconnect_reason.take() {
            let _ = tx.send(reason);
        }
    }
}

impl SignalWebSocketProcess {
    async fn process_frame(
        &mut self,
        frame: Bytes,
    ) -> Result<(), ServiceError> {
        use prost::Message;
        let msg = WebSocketMessage::decode(frame)?;
        if let Some(request) = &msg.request {
            tracing::trace!(
                msg_type =? msg.r#type(),
                request.id,
                request.verb,
                request.path,
                request_body_size_bytes = request.body.as_ref().map(|x| x.len()).unwrap_or(0),
                ?request.headers,
                "decoded WebSocketMessage request"
            );
        } else if let Some(response) = &msg.response {
            tracing::trace!(
                msg_type =? msg.r#type(),
                response.status,
                response.message,
                response_body_size_bytes = response.body.as_ref().map(|x| x.len()).unwrap_or(0),
                ?response.headers,
                response.id,
                "decoded WebSocketMessage response"
            );
        } else {
            tracing::debug!("decoded {msg:?}");
        }

        use web_socket_message::Type;
        match (msg.r#type(), msg.request, msg.response) {
            (Type::Unknown, _, _) => Err(ServiceError::InvalidFrame {
                reason: "unknown frame type",
            }),
            (Type::Request, Some(request), _) => {
                let (sink, recv) = oneshot::channel();
                tracing::trace!("sending request with body");
                self.request_sink.send((request, sink)).await.map_err(
                    |_| ServiceError::WsClosing {
                        reason: "request handler failed",
                    },
                )?;
                self.outgoing_responses.push(Box::pin(recv));

                Ok(())
            },
            (Type::Request, None, _) => Err(ServiceError::InvalidFrame {
                reason: "type was request, but does not contain request",
            }),
            (Type::Response, _, Some(response)) => {
                if let Some(id) = response.id {
                    if let Some(responder) = self.outgoing_requests.remove(&id)
                    {
                        if let Err(e) = responder.send(Ok(response)) {
                            tracing::warn!(
                                "Could not deliver response for id {}: {:?}",
                                id,
                                e
                            );
                        }
                    } else if let Some(_x) =
                        self.outgoing_keep_alive_set.take(&id)
                    {
                        let status = reqwest::StatusCode::from_u16(
                            response.status() as _,
                        )
                        .map_err(|e| {
                            ServiceError::IO(std::io::Error::other(format!(
                                "invalid http status code {} - {e}",
                                response.status()
                            )))
                        })?;
                        if !status.is_success() {
                            tracing::warn!(
                                %status,
                                "response code for keep-alive not successful"
                            );
                            return Err(ServiceError::UnhandledResponseCode {
                                status,
                                body: String::from_utf8_lossy(response.body())
                                    .into_owned(),
                            });
                        }
                    } else {
                        tracing::warn!(
                            ?response,
                            "response for non existing request"
                        );
                    }
                }

                Ok(())
            },
            (Type::Response, _, None) => Err(ServiceError::InvalidFrame {
                reason: "type was response, but does not contain response",
            }),
        }
    }

    fn next_request_id(&self) -> u64 {
        use rand::Rng;
        let mut rng = rand::rng();
        loop {
            let id = rng.random();
            if !self.outgoing_requests.contains_key(&id) {
                return id;
            }
        }
    }

    async fn run(mut self) -> Result<(), ServiceError> {
        let mut ka_interval = tokio::time::interval_at(
            Instant::now(),
            push_service::KEEPALIVE_TIMEOUT_SECONDS,
        );

        loop {
            futures::select! {
                _ = ka_interval.tick().fuse() => {
                    use prost::Message;
                    if !self.outgoing_keep_alive_set.is_empty() {
                        tracing::warn!("Websocket will be closed due to failed keepalives.");
                        // Record the reason before `close()` consumes `self.ws`.
                        self.set_disconnect_reason(DisconnectReason::KeepaliveTimeout);
                        if let Err(e) = self.ws.close(reqwest_websocket::CloseCode::Away, None).await {
                            tracing::debug!("Could not close WebSocket: {:?}", e);
                        }
                        self.outgoing_keep_alive_set.clear();
                        break;
                    }
                    tracing::debug!("sending keep-alive");
                    let request = WebSocketRequestMessage::new(Method::GET)
                        .id(self.next_request_id())
                        .path(&self.keep_alive_path)
                        .build();
                    self.outgoing_keep_alive_set.insert(request.id.unwrap());
                    let msg = WebSocketMessage {
                        r#type: Some(web_socket_message::Type::Request.into()),
                        request: Some(request),
                        ..Default::default()
                    };
                    let buffer = msg.encode_to_vec();
                    if let Err(e) = self.ws.send(reqwest_websocket::Message::Binary(buffer.into())).await {
                        tracing::info!("Websocket sink has closed: {:?}.", e);
                        break;
                    };
                },
                // Process requests from the application, forward them to Signal
                x = self.requests.next() => {
                    match x {
                        Some((mut request, responder)) => {
                            use prost::Message;

                            // Regenerate ID if already in the table
                            request.id = Some(
                                request
                                    .id
                                    .filter(|x| !self.outgoing_requests.contains_key(x))
                                    .unwrap_or_else(|| self.next_request_id()),
                            );
                            tracing::trace!(
                                request.id,
                                request.verb,
                                request.path,
                                request_body_size_bytes = request.body.as_ref().map(|x| x.len()),
                                ?request.headers,
                                "sending WebSocketRequestMessage",
                            );

                            self.outgoing_requests.insert(request.id.unwrap(), responder);
                            let msg = WebSocketMessage {
                                r#type: Some(web_socket_message::Type::Request.into()),
                                request: Some(request),
                                ..Default::default()
                            };
                            let buffer = msg.encode_to_vec();
                            self.ws.send(reqwest_websocket::Message::Binary(buffer.into())).await?
                        }
                        None => {
                            debug!("end of application request stream; websocket closing");
                            return Ok(());
                        }
                    }
                }
                // Incoming websocket message
                web_socket_item = self.ws.next().fuse() => {
                    use reqwest_websocket::Message;
                    match web_socket_item {
                        Some(Ok(Message::Close { code, reason })) => {
                            tracing::warn!(%code, reason, "websocket closed");
                            self.set_disconnect_reason(DisconnectReason::from_close(
                                u16::from(code),
                                reason.to_string(),
                            ));
                            break;
                        },
                        Some(Ok(Message::Binary(frame))) => {
                            self.process_frame(frame).await?;
                        }
                        Some(Ok(Message::Ping(_))) => {
                            tracing::trace!("received ping");
                        }
                        Some(Ok(Message::Pong(_))) => {
                            tracing::trace!("received pong");
                        }
                        Some(Ok(Message::Text(_))) => {
                            tracing::trace!("received text (unsupported, skipping)");
                        }
                        Some(Err(e)) => {
                            self.set_disconnect_reason(DisconnectReason::Transport);
                            return Err(e.into());
                        }
                        None => {
                            self.set_disconnect_reason(DisconnectReason::Transport);
                            return Err(ServiceError::WsClosing {
                                reason: "end of web request stream; socket closing"
                            });
                        }
                    }
                }
                response = self.outgoing_responses.next() => {
                    use prost::Message;
                    match response {
                        Some(Ok(response)) => {
                            tracing::trace!("sending response {:?}", response);

                            let msg = WebSocketMessage {
                                r#type: Some(web_socket_message::Type::Response.into()),
                                response: Some(response),
                                ..Default::default()
                            };
                            let buffer = msg.encode_to_vec();
                            self.ws.send(buffer.into()).await?;
                        }
                        Some(Err(error)) => {
                            tracing::error!(%error, "could not generate response to a Signal request; responder was canceled. continuing.");
                        }
                        None => {
                            unreachable!("outgoing responses should never fuse")
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

impl<C: WebSocketType> SignalWebSocket<C> {
    fn inner_locked(&self) -> MutexGuard<'_, SignalWebSocketInner> {
        self.inner.lock().unwrap()
    }

    pub fn new(
        ws: WebSocket,
        keep_alive_path: String,
        unidentified_push_service: PushService,
    ) -> (Self, impl Future<Output = ()>) {
        // Create process
        let (incoming_request_sink, incoming_request_stream) =
            mpsc::unbounded();
        let (outgoing_request_sink, outgoing_requests) = mpsc::channel(1);
        let (disconnect_tx, disconnect_rx) = oneshot::channel();

        let process = SignalWebSocketProcess {
            keep_alive_path,
            requests: outgoing_requests,
            request_sink: incoming_request_sink,
            outgoing_requests: HashMap::default(),
            outgoing_keep_alive_set: HashSet::new(),
            // Initializing the FuturesUnordered with a `pending` future means it will never fuse
            // itself, so an "empty" FuturesUnordered will still allow new futures to be added.
            outgoing_responses: vec![
                Box::pin(futures::future::pending()) as BoxFuture<_>
            ]
            .into_iter()
            .collect(),
            ws,
            disconnect_reason: Some(disconnect_tx),
        };
        let process = process.run().map(|x| match x {
            Ok(()) => (),
            Err(e) => {
                tracing::error!("SignalWebSocket: {}", e);
            },
        });

        (
            Self {
                _type: PhantomData,
                request_sink: outgoing_request_sink,
                unidentified_push_service,
                inner: Arc::new(Mutex::new(SignalWebSocketInner {
                    stream: Some(SignalRequestStream {
                        inner: incoming_request_stream,
                    }),
                    disconnect_reason: Some(disconnect_rx),
                })),
            },
            process,
        )
    }

    pub fn servers(&self) -> SignalServers {
        self.unidentified_push_service.servers
    }

    pub fn is_closed(&self) -> bool {
        self.request_sink.is_closed()
    }

    pub fn is_used(&self) -> bool {
        self.inner_locked().stream.is_none()
    }

    pub(crate) fn take_request_stream(
        &mut self,
    ) -> Option<SignalRequestStream> {
        self.inner_locked().stream.take()
    }

    pub(crate) fn take_disconnect_reason(
        &mut self,
    ) -> Option<oneshot::Receiver<DisconnectReason>> {
        self.inner_locked().disconnect_reason.take()
    }

    pub(crate) fn return_request_stream(&mut self, r: SignalRequestStream) {
        self.inner_locked().stream.replace(r);
    }

    // XXX Ideally, this should take an *async* closure, then we could get rid of the
    // `take_request_stream` and `return_request_stream`.
    pub async fn with_request_stream<
        R: 'static,
        F: FnOnce(&mut SignalRequestStream) -> R,
    >(
        &mut self,
        f: F,
    ) -> R {
        let mut s = self
            .inner_locked()
            .stream
            .take()
            .expect("request stream invariant");
        let r = f(&mut s);
        self.inner_locked().stream.replace(s);
        r
    }

    pub fn request(
        &mut self,
        r: WebSocketRequestMessage,
    ) -> impl Future<Output = Result<WebSocketResponseMessage, ServiceError>>
    {
        let (sink, recv): (
            oneshot::Sender<Result<WebSocketResponseMessage, ServiceError>>,
            _,
        ) = oneshot::channel();

        let mut request_sink = self.request_sink.clone();
        async move {
            if let Err(_e) = request_sink.send((r, sink)).await {
                return Err(ServiceError::WsClosing {
                    reason: "WebSocket closing while sending request",
                });
            }
            // Handle the oneshot sender error for dropped senders.
            match recv.await {
                Ok(x) => x,
                Err(_) => Err(ServiceError::WsClosing {
                    reason: "WebSocket closing while waiting for a response",
                }),
            }
        }
    }

    pub(crate) async fn request_json<T>(
        &mut self,
        r: WebSocketRequestMessage,
    ) -> Result<T, ServiceError>
    where
        for<'de> T: serde::Deserialize<'de>,
    {
        self.request(r)
            .await?
            .service_error_for_status()
            .await?
            .json()
            .await
    }
}

impl WebSocketResponseMessage {
    pub async fn service_error_for_status(self) -> Result<Self, ServiceError> {
        super::push_service::response::service_error_for_status(self).await
    }

    pub async fn json<T: for<'a> serde::Deserialize<'a>>(
        &self,
    ) -> Result<T, ServiceError> {
        self.body
            .as_ref()
            .ok_or(ServiceError::UnsupportedContent)
            .and_then(|b| serde_json::from_slice(b).map_err(Into::into))
    }
}

#[cfg(test)]
mod tests {
    use super::DisconnectReason;

    #[test]
    fn disconnect_reason_from_close_maps_known_codes() {
        // 4401/4409 mirror libsignal-net's env.rs close codes.
        assert!(matches!(
            DisconnectReason::from_close(4409, String::new()),
            DisconnectReason::ConnectedElsewhere
        ));
        assert!(matches!(
            DisconnectReason::from_close(4401, String::new()),
            DisconnectReason::ConnectionInvalidated
        ));
        // Anything else keeps the raw code/reason for the consumer to inspect.
        assert!(matches!(
            DisconnectReason::from_close(1000, "bye".to_owned()),
            DisconnectReason::ServerClosed { code: 1000, .. }
        ));
    }
}
