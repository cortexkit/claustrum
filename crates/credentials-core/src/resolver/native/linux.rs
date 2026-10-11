//! Minimal synchronous Secret Service protocol. Never call Unlock or Prompt, even
//! if a collection locks between the preflight and a write/delete. All bus calls
//! have a bounded timeout, and a returned prompt path is rejected, not executed.

use super::*;
use std::{collections::HashMap, time::Duration};
use zbus::{
    blocking::{connection::Builder, Connection, Proxy},
    proxy::CacheProperties,
    zvariant::{OwnedObjectPath, OwnedValue, Value},
};
use zeroize::Zeroizing;

const DESTINATION: &str = "org.freedesktop.secrets";
const ROOT: &str = "/org/freedesktop/secrets";
const SERVICE: &str = "org.freedesktop.Secret.Service";
const COLLECTION: &str = "org.freedesktop.Secret.Collection";
const ITEM: &str = "org.freedesktop.Secret.Item";
type Secret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

fn bus_error(e: impl ToString) -> MasterKeyError {
    unavailable("secret-service", e)
}

fn no_prompt(path: &OwnedObjectPath) -> Result<(), MasterKeyError> {
    refuse_prompt_path(path.as_str())
}

struct Session {
    connection: Connection,
    path: OwnedObjectPath,
    collection: OwnedObjectPath,
}

impl Session {
    fn proxy<'a>(&'a self, path: &'a str, interface: &'a str) -> Result<Proxy<'a>, MasterKeyError> {
        zbus::blocking::proxy::Builder::<Proxy<'a>>::new(&self.connection)
            .destination(DESTINATION)
            .map_err(bus_error)?
            .path(path)
            .map_err(bus_error)?
            .interface(interface)
            .map_err(bus_error)?
            .cache_properties(CacheProperties::No)
            .build()
            .map_err(bus_error)
    }

    fn connect() -> Result<Self, MasterKeyError> {
        let connection = Builder::session()
            .map_err(bus_error)?
            .method_timeout(Duration::from_secs(5))
            .build()
            .map_err(bus_error)?;
        let service = Proxy::new(&connection, DESTINATION, ROOT, SERVICE).map_err(bus_error)?;
        let collection: OwnedObjectPath = service
            .call("ReadAlias", &("default",))
            .map_err(bus_error)?;
        if collection.as_str() == "/" {
            return Err(bus_error("no default collection is provisioned"));
        }
        let collection_proxy =
            Proxy::new(&connection, DESTINATION, collection.as_str(), COLLECTION)
                .map_err(bus_error)?;
        if collection_proxy
            .get_property::<bool>("Locked")
            .map_err(bus_error)?
        {
            return Err(bus_error("default collection is locked"));
        }
        // The authenticated per-user session bus carries the secret. The Plain
        // session avoids hand-written cryptography; custody at rest remains in the
        // keyring, and another process running as this user can access it regardless.
        let (_, path): (OwnedValue, OwnedObjectPath) = service
            .call("OpenSession", &("plain", Value::from("")))
            .map_err(bus_error)?;
        drop(collection_proxy);
        drop(service);
        Ok(Self {
            connection,
            path,
            collection,
        })
    }

    fn items(&self, service: &str, account: &str) -> Result<Vec<OwnedObjectPath>, MasterKeyError> {
        let collection = self.proxy(self.collection.as_str(), COLLECTION)?;
        if collection
            .get_property::<bool>("Locked")
            .map_err(bus_error)?
        {
            return Err(bus_error("default collection is locked"));
        }
        collection
            .call("SearchItems", &(attributes(service, account),))
            .map_err(bus_error)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Ok(proxy) = self.proxy(self.path.as_str(), "org.freedesktop.Secret.Session") {
            let _: Result<(), _> = proxy.call("Close", &());
        }
    }
}

fn attributes<'a>(service: &'a str, account: &'a str) -> HashMap<&'a str, &'a str> {
    // The schema attribute keeps another application's generic service/account item
    // from ever matching a vault slot.
    HashMap::from([
        ("xdg:schema", "io.cortexkit.claustrum.MasterKey"),
        ("service", service),
        ("account", account),
    ])
}

impl MasterKeyStore for SecretService {
    fn load_slot(&self, dir: &Path, slot: KeySlot) -> Result<Option<MasterKey>, MasterKeyError> {
        let service = KeychainCli::service_for(dir)?;
        let session = Session::connect()?;
        let items = session.items(&service, &KeychainCli::account_for(slot))?;
        if items.len() > 1 {
            return Err(bus_error(
                "multiple items match the vault slot; remove duplicates before retrying",
            ));
        }
        let Some(path) = items.first() else {
            return Ok(None);
        };
        let item = session.proxy(path.as_str(), ITEM)?;
        if item.get_property::<bool>("Locked").map_err(bus_error)? {
            return Err(bus_error("master-key item is locked"));
        }
        let (secret_session, parameters, bytes, content_type): Secret = item
            .call("GetSecret", &(&session.path,))
            .map_err(bus_error)?;
        let bytes = Zeroizing::new(bytes);
        if secret_session != session.path || !parameters.is_empty() || content_type != "text/plain"
        {
            return Err(bus_error("invalid plain-session secret response"));
        }
        decode_secret(&bytes).map(Some)
    }

    fn store_slot(&self, dir: &Path, slot: KeySlot, key: &MasterKey) -> Result<(), MasterKeyError> {
        write_slot(dir, slot, key, |service, account, encoded| {
            let session = Session::connect()?;
            let collection = session.proxy(session.collection.as_str(), COLLECTION)?;
            let properties = HashMap::from([
                (
                    "org.freedesktop.Secret.Item.Label",
                    Value::from(format!("{service}/{account}")),
                ),
                (
                    "org.freedesktop.Secret.Item.Attributes",
                    Value::from(attributes(service, account)),
                ),
            ]);
            let secret = (
                &session.path,
                Vec::<u8>::new(),
                encoded.as_bytes(),
                "text/plain",
            );
            let (item, prompt): (OwnedObjectPath, OwnedObjectPath) = collection
                .call("CreateItem", &(properties, secret, true))
                .map_err(bus_error)?;
            no_prompt(&prompt)?;
            if item.as_str() == "/" {
                return Err(bus_error("store did not return an item"));
            }
            Ok(())
        })
    }

    fn clear_slot(&self, dir: &Path, slot: KeySlot) -> Result<(), MasterKeyError> {
        let service = KeychainCli::service_for(dir)?;
        let session = Session::connect()?;
        for path in session.items(&service, &KeychainCli::account_for(slot))? {
            let item = session.proxy(path.as_str(), ITEM)?;
            let prompt: OwnedObjectPath = item.call("Delete", &()).map_err(bus_error)?;
            no_prompt(&prompt)?;
        }
        Ok(())
    }
}
