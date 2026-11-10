use chrono::{DateTime, Utc};
use futures::{
    channel::{
        mpsc::{self, Sender},
        oneshot,
    },
    prelude::*,
};
use prost::Message;

pub use crate::{
    configuration::ServiceCredentials,
    proto::{
        web_socket_message, Envelope, WebSocketMessage,
        WebSocketRequestMessage, WebSocketResponseMessage,
    },
};

use crate::{
    push_service::ServiceError,
    websocket::{self, SignalWebSocket},
};

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Incoming {
    /// One queued envelope. `server_delivered_timestamp` is the frame's
    /// `X-Signal-Timestamp`: when the server handed this envelope over, as
    /// opposed to `Envelope::server_timestamp`, when it accepted it. Their
    /// difference is how long the message sat in the queue, which call
    /// signalling needs to expire stale offers. `None` when the header is
    /// missing; treat that as "just delivered".
    Envelope {
        envelope: Envelope,
        server_delivered_timestamp: Option<DateTime<Utc>>,
    },
    QueueEmpty,
    /// Terminal item: the identified websocket closed. Carries the typed reason
    /// so the consumer can classify the drop (unlink / connected-elsewhere /
    /// transient) and decide whether to reconnect. Yielded once, last.
    Disconnected(websocket::DisconnectReason),
}

pub struct MessagePipe {
    ws: SignalWebSocket<websocket::Identified>,
}

impl MessagePipe {
    pub fn from_socket(ws: SignalWebSocket<websocket::Identified>) -> Self {
        MessagePipe { ws }
    }

    /// Return a SignalWebSocket for sending messages and other purposes beyond receiving messages.
    pub fn ws(&self) -> SignalWebSocket<websocket::Identified> {
        self.ws.clone()
    }

    /// Worker task that processes the websocket into Envelopes
    async fn run(
        mut self,
        mut sink: Sender<Result<Incoming, ServiceError>>,
    ) -> Result<(), mpsc::SendError> {
        let mut ws = self.ws.clone();
        let mut stream = ws
            .take_request_stream()
            .expect("web socket request handler not in use");
        let disconnect_reason = ws.take_disconnect_reason();

        while let Some((request, responder)) = stream.next().await {
            // WebsocketConnection::onMessage(ByteString)
            if let Some(env) =
                self.process_request(request, responder).await.transpose()
            {
                sink.send(env).await?;
            } else {
                tracing::trace!("got empty message in websocket");
            }
        }

        ws.return_request_stream(stream);

        // The worker exited: surface why as a final stream item so the consumer
        // can classify the disconnect. Falls back to `Transport` if the worker
        // ended without recording a reason (e.g. its sender was dropped).
        if let Some(rx) = disconnect_reason {
            let reason =
                rx.await.unwrap_or(websocket::DisconnectReason::Transport);
            sink.send(Ok(Incoming::Disconnected(reason))).await?;
        }

        Ok(())
    }

    async fn process_request(
        &mut self,
        request: WebSocketRequestMessage,
        responder: oneshot::Sender<WebSocketResponseMessage>,
    ) -> Result<Option<Incoming>, ServiceError> {
        // Java: MessagePipe::read
        let response = WebSocketResponseMessage::from_request(&request);

        // XXX Change the signature of this method to yield an enum of Envelope and EndOfQueue
        let result = if request.is_signal_service_envelope() {
            let body = if let Some(body) = request.body.as_ref() {
                body
            } else {
                return Err(ServiceError::InvalidFrame {
                    reason: "request without body.",
                });
            };
            Some(Incoming::Envelope {
                envelope: Envelope::decode(body.as_slice())?,
                server_delivered_timestamp: server_delivered_timestamp(
                    &request.headers,
                ),
            })
        } else if request.is_queue_empty() {
            Some(Incoming::QueueEmpty)
        } else {
            None
        };

        responder
            .send(response)
            .map_err(|_| ServiceError::WsClosing {
                reason: "could not respond to message pipe request",
            })?;

        Ok(result)
    }

    /// Returns the stream of `Envelope`s
    ///
    /// Envelopes yielded are acknowledged.
    pub fn stream(self) -> impl Stream<Item = Result<Incoming, ServiceError>> {
        let (sink, stream) = mpsc::channel(1);

        let stream = stream.map(Some);
        let runner = self.run(sink).map(|e| {
            tracing::info!("sink was closed: {:?}", e);
            None
        });

        let combined = futures::stream::select(stream, runner.into_stream());
        combined.filter_map(|x| async { x })
    }
}

/// The `X-Signal-Timestamp` header of a message frame, as the server writes
/// it: milliseconds since the epoch. Header names are matched
/// case-insensitively because the proto carries them as free-form
/// `Name:Value` strings.
fn server_delivered_timestamp(headers: &[String]) -> Option<DateTime<Utc>> {
    headers.iter().find_map(|header| {
        let (name, value) = header.split_once(':')?;
        if !name.trim().eq_ignore_ascii_case("x-signal-timestamp") {
            return None;
        }
        let millis: i64 = value.trim().parse().ok()?;
        DateTime::from_timestamp_millis(millis)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_delivery_timestamp_header() {
        let headers = vec![
            "Content-Type:application/octet-stream".to_string(),
            "x-signal-timestamp: 1700000000123".to_string(),
        ];
        assert_eq!(
            server_delivered_timestamp(&headers),
            DateTime::from_timestamp_millis(1_700_000_000_123)
        );
    }

    #[test]
    fn missing_or_malformed_header_is_none() {
        assert_eq!(server_delivered_timestamp(&[]), None);
        assert_eq!(
            server_delivered_timestamp(&["X-Signal-Timestamp:soon".into()]),
            None
        );
        assert_eq!(
            server_delivered_timestamp(&["X-Signal-Timestamp".into()]),
            None
        );
    }
}
