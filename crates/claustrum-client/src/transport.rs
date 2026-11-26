use super::*;

/// Byte I/O only: operation bodies, reply decoding and watch policy live above it.
pub(super) trait CredentialTransport: Send {
    fn request(
        &mut self,
        body: Vec<u8>,
    ) -> CredentialResolverFuture<'_, Result<Vec<u8>, CredentialResolverError>>;
    fn subscribe(
        &mut self,
        body: Vec<u8>,
    ) -> CredentialResolverFuture<'_, Result<u64, CredentialResolverError>>;
    fn next_watch(
        &mut self,
        corr: u64,
    ) -> CredentialResolverFuture<'_, Result<WatchFrame, CredentialResolverError>>;
    fn cancel_watch(&mut self, corr: u64) -> CredentialResolverFuture<'_, ()>;
}

pub(super) enum WatchFrame {
    Data(Vec<u8>),
    Response(Vec<u8>),
    End,
    Error(CredentialResolverError),
}

pub(super) async fn sensitive_request(
    transport: &mut impl CredentialTransport,
    request: Secret<Vec<u8>>,
) -> Result<Secret<Vec<u8>>, CredentialResolverError> {
    // The transport owns framing and socket buffers. The operation's own
    // serialized request and returned reply use redacted, zeroizing buffers.
    transport
        .request(request.expose().clone())
        .await
        .map(Secret::new)
}

pub(super) async fn credential_request(
    transport: &mut (impl CredentialTransport + ?Sized),
    request: Value,
    operation: &str,
) -> Result<Value, CredentialResolverError> {
    let reply = transport.request(encode_request(&request)?).await?;
    serde_json::from_slice(&reply).map_err(|_| {
        CredentialResolverError::new(
            CredentialErrorClass::InvalidResponse,
            format!("{operation} reply is not valid JSON"),
        )
    })
}

pub(super) fn encode_request(body: &Value) -> Result<Vec<u8>, CredentialResolverError> {
    serde_json::to_vec(body).map_err(|_| {
        CredentialResolverError::new(
            CredentialErrorClass::Permanent,
            "credential request encoding failed",
        )
    })
}

impl CredentialTransport for ClaustrumConsumer {
    fn request(
        &mut self,
        body: Vec<u8>,
    ) -> CredentialResolverFuture<'_, Result<Vec<u8>, CredentialResolverError>> {
        Box::pin(async move {
            let corr = self.next_correlation();
            self.write_bytes(
                self.route_channel,
                self.route_epoch,
                corr,
                Priority::Interactive,
                body,
            )
            .await?;
            let reply = self
                .read_reply(self.route_channel, self.route_epoch, corr)
                .await?;
            if reply.header.ty == FrameType::Error {
                return Err(decode_established_route_wire_error(
                    reply.header.flags,
                    &reply.body,
                ));
            }
            Ok(reply.body)
        })
    }

    fn subscribe(
        &mut self,
        body: Vec<u8>,
    ) -> CredentialResolverFuture<'_, Result<u64, CredentialResolverError>> {
        Box::pin(async move {
            let corr = self.next_correlation();
            self.write_bytes(
                self.route_channel,
                self.route_epoch,
                corr,
                Priority::Interactive,
                body,
            )
            .await?;
            Ok(corr)
        })
    }

    fn next_watch(
        &mut self,
        corr: u64,
    ) -> CredentialResolverFuture<'_, Result<WatchFrame, CredentialResolverError>> {
        Box::pin(async move {
            loop {
                let frame = read_frame(&mut self.stream)
                    .await
                    .ok()
                    .flatten()
                    .ok_or_else(|| {
                        CredentialResolverError::transport("scoped watch connection lost")
                    })?;
                if frame.header.channel != self.route_channel
                    || frame.header.epoch != self.route_epoch
                {
                    continue;
                }
                if frame.header.ty == FrameType::Goodbye {
                    return Err(CredentialResolverError::unclassified(
                        "route_closed",
                        "scoped watch route closed",
                    ));
                }
                if frame.header.corr != corr {
                    continue;
                }
                match frame.header.ty {
                    FrameType::StreamData => return Ok(WatchFrame::Data(frame.body)),
                    FrameType::Response => return Ok(WatchFrame::Response(frame.body)),
                    FrameType::StreamEnd => return Ok(WatchFrame::End),
                    FrameType::Error => {
                        return Ok(WatchFrame::Error(decode_established_route_wire_error(
                            frame.header.flags,
                            &frame.body,
                        )))
                    }
                    _ => {}
                }
            }
        })
    }

    fn cancel_watch(&mut self, corr: u64) -> CredentialResolverFuture<'_, ()> {
        Box::pin(async move {
            if let Ok(cancel) = Frame::build(
                FrameType::Cancel,
                Flags::new(false, Priority::Interactive, false),
                self.route_channel,
                self.route_epoch,
                corr,
                vec![],
            ) {
                let _ = tokio::time::timeout(
                    CREDENTIAL_READ_TIMEOUT,
                    write_frame(&mut self.stream, &cancel),
                )
                .await;
            }
        })
    }
}
