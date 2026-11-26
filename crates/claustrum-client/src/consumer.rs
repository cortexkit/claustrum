use super::transport::{CredentialTransport, WatchFrame};
use super::*;
use subc_client_rs::{
    CallError, CallOptions, CloseRouteOptions, SubcConsumer, SubscribeOptions, Subscription,
    SubscriptionEnd,
};
use subc_protocol::{BindIdentity, RouteTarget};

pub(super) struct ConsumerConnector(pub Arc<SubcConsumer>);
pub(super) struct ModuleSecretConnector(pub Arc<SubcConsumer>);

impl CredentialConsumerConnector for ModuleSecretConnector {
    fn connect(
        &self,
    ) -> CredentialResolverFuture<
        '_,
        Result<Box<dyn CredentialConsumerConnection>, CredentialResolverError>,
    > {
        connect(
            Arc::clone(&self.0),
            BindIdentity::new("callosum-self".to_owned(), "credential-resolver".to_owned()),
        )
    }
}

fn connect(
    consumer: Arc<SubcConsumer>,
    identity: BindIdentity,
) -> CredentialResolverFuture<
    'static,
    Result<Box<dyn CredentialConsumerConnection>, CredentialResolverError>,
> {
    Box::pin(async move {
        let handle = consumer
            .open_route(target(), identity, options())
            .await
            .map_err(decode_open_error)?;
        Ok(Box::new(ConsumerConnection {
            consumer,
            handle,
            subscription: None,
        }) as Box<dyn CredentialConsumerConnection>)
    })
}

impl CredentialConsumerConnector for ConsumerConnector {
    fn connect(
        &self,
    ) -> CredentialResolverFuture<
        '_,
        Result<Box<dyn CredentialConsumerConnection>, CredentialResolverError>,
    > {
        connect(Arc::clone(&self.0), identity())
    }

    fn connect_policy_watch(
        &self,
    ) -> CredentialResolverFuture<
        '_,
        Result<Box<dyn CredentialConsumerConnection>, CredentialResolverError>,
    > {
        // The SDK shares routes with the same bind identity. Use a separate bind
        // from unary calls and scoped watches, without overriding the attested principal.
        connect(
            Arc::clone(&self.0),
            BindIdentity::new("claustrum-client".to_owned(), "policy-watch".to_owned()),
        )
    }
}

struct ConsumerConnection {
    consumer: Arc<SubcConsumer>,
    handle: subc_client_rs::RouteHandle,
    subscription: Option<Subscription>,
}

fn target() -> RouteTarget {
    RouteTarget::ManagementSurface {
        module_id: CREDENTIAL_MODULE_ID.to_owned(),
    }
}

fn identity() -> BindIdentity {
    BindIdentity::new(
        "claustrum-client".to_owned(),
        "credential-resolver".to_owned(),
    )
}

fn options() -> CallOptions {
    CallOptions {
        timeout: CREDENTIAL_CALL_DEADLINE,
        consumer_identity: None,
        ..Default::default()
    }
}

fn decode_open_error(error: CallError) -> CredentialResolverError {
    if let CallError::Module(body) = error {
        return classify_route_open_error(body);
    }
    decode_sdk_error(error)
}

fn decode_sdk_error(error: CallError) -> CredentialResolverError {
    if let Some(body) = error.route_open_refusal() {
        return classify_route_open_error(body.clone());
    }
    if let Some(code) = error.code() {
        return classify_route_open_error(ErrorBody {
            code: code.to_owned(),
            message: "credential SDK request refused".to_owned(),
            detail: None,
        });
    }
    CredentialResolverError::transport("credential SDK connection failed")
}

impl ConsumerConnection {
    async fn decode_established_frame(&mut self, body: ErrorBody) -> CredentialResolverError {
        // The SDK does not expose reply flags yet. Pass them through when it does
        // so the daemon-origin check can recognize these refusals.
        let error = classify_established_route_error(Flags(0), body);
        if error.established_route_dead {
            // Dropping this connection wrapper alone leaves the dead handle cached in the SDK.
            let _ = self
                .consumer
                .close_handle(&self.handle, CloseRouteOptions::default())
                .await;
        }
        error
    }
}

impl CredentialConsumerConnection for ConsumerConnection {
    fn sensitive_request(
        &mut self,
        request: Secret<Vec<u8>>,
    ) -> CredentialResolverFuture<'_, Result<Secret<Vec<u8>>, CredentialResolverError>> {
        Box::pin(transport::sensitive_request(self, request))
    }
    fn into_scoped_watch(
        self: Box<Self>,
        enrollment_token: Option<String>,
    ) -> CredentialResolverFuture<'static, Result<ScopedWatch, CredentialResolverError>> {
        Box::pin(watch::start_scoped_watch(*self, enrollment_token))
    }

    fn into_policy_watch(
        self: Box<Self>,
    ) -> CredentialResolverFuture<'static, Result<PolicyWatch, CredentialResolverError>> {
        Box::pin(watch::start_policy_watch(*self))
    }

    fn credential_request<'a>(
        &'a mut self,
        request: Value,
        operation: &'a str,
    ) -> CredentialResolverFuture<'a, Result<Value, CredentialResolverError>> {
        Box::pin(transport::credential_request(self, request, operation))
    }
}

impl CredentialTransport for ConsumerConnection {
    fn request(
        &mut self,
        body: Vec<u8>,
    ) -> CredentialResolverFuture<'_, Result<Vec<u8>, CredentialResolverError>> {
        Box::pin(async move {
            // request()/call() can replay route_busy refusals. Reserve/send keeps
            // every unary attempt single-shot, including non-idempotent seals.
            let body = subc_client_rs::RequestBody::new(body).map_err(decode_sdk_error)?;
            let reservation = self
                .consumer
                .reserve(
                    &self.handle,
                    tokio::time::Instant::now() + CREDENTIAL_CALL_DEADLINE,
                )
                .await
                .map_err(decode_sdk_error)?;
            let (_, reply) = reservation.send(body, options());
            match reply.await {
                Ok(body) => Ok(body),
                Err(CallError::Module(body)) => Err(self.decode_established_frame(body).await),
                Err(error) => Err(decode_sdk_error(error)),
            }
        })
    }

    fn subscribe(
        &mut self,
        body: Vec<u8>,
    ) -> CredentialResolverFuture<'_, Result<u64, CredentialResolverError>> {
        Box::pin(async move {
            self.subscription = Some(
                self.consumer
                    .subscribe_route(
                        &self.handle,
                        body,
                        SubscribeOptions {
                            consumer_identity: None,
                            event_buffer: 32,
                            ..Default::default()
                        },
                    )
                    .await
                    .map_err(decode_sdk_error)?,
            );
            Ok(0)
        })
    }

    fn next_watch(
        &mut self,
        _corr: u64,
    ) -> CredentialResolverFuture<'_, Result<WatchFrame, CredentialResolverError>> {
        Box::pin(async move {
            let Some(subscription) = self.subscription.as_mut() else {
                return Err(CredentialResolverError::transport(
                    "scoped watch read before it was opened",
                ));
            };
            // The SDK closes the event channel after queuing all prior notices.
            // Drain it before observing the terminal result to preserve wire order.
            if let Some(body) = subscription.events().recv().await {
                return Ok(WatchFrame::Data(body));
            }
            match subscription.ended().await {
                SubscriptionEnd::Response(body) => Ok(WatchFrame::Response(body)),
                SubscriptionEnd::StreamEnd => Ok(WatchFrame::End),
                SubscriptionEnd::Error(body) => {
                    Ok(WatchFrame::Error(self.decode_established_frame(body).await))
                }
                SubscriptionEnd::RouteClosed { .. } => Err(CredentialResolverError::unclassified(
                    "route_closed",
                    "scoped watch route closed",
                )),
                SubscriptionEnd::Backpressure => Err(CredentialResolverError::transport(
                    "scoped watch consumer lagged",
                )),
                _ => Err(CredentialResolverError::transport(
                    "scoped watch connection lost",
                )),
            }
        })
    }

    fn cancel_watch(&mut self, _corr: u64) -> CredentialResolverFuture<'_, ()> {
        Box::pin(async move {
            if let Some(subscription) = self.subscription.take() {
                let _ = subscription.unsubscribe();
            }
        })
    }
}

#[cfg(test)]
mod tests;
