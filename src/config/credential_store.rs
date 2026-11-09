//! Narrow compatibility adapter for the platform stores formerly selected by keyring v3.
//! No process-global default store, cached connection failure, or credential migration.

use keyring_core::api::CredentialStoreApi;
#[cfg(any(target_os = "linux", test))]
use keyring_core::Error;
use keyring_core::Result;

pub(crate) struct Entry {
    inner: keyring_core::Entry,
    #[cfg(target_os = "linux")]
    service: String,
    #[cfg(target_os = "linux")]
    user: String,
}

impl Entry {
    pub(crate) fn new(service: &str, user: &str) -> Result<Self> {
        #[cfg(target_os = "linux")]
        let inner = dbus_secret_service_keyring_store::Store::new()?.build(
            service,
            user,
            Some(&std::collections::HashMap::from([("target", "default")])),
        )?;
        #[cfg(target_os = "macos")]
        let inner =
            apple_native_keyring_store::keychain::Store::new()?.build(service, user, None)?;
        // Windows previously had a featureless keyring v3 mock. Do not silently
        // introduce Credential Manager: primary storage remains DPAPI. Other
        // unsupported platforms also retain a fresh, nonpersistent mock entry.
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let inner = keyring_core::mock::Store::new()?.build(service, user, None)?;
        Ok(Self {
            inner,
            #[cfg(target_os = "linux")]
            service: service.to_owned(),
            #[cfg(target_os = "linux")]
            user: user.to_owned(),
        })
    }

    pub(crate) fn get_password(&self) -> Result<String> {
        let result = self.inner.get_password();
        #[cfg(target_os = "linux")]
        let result = only_if_missing(result, || {
            self.with_legacy_item(|item| {
                let bytes = item.get_secret().map_err(platform_failure)?;
                String::from_utf8(bytes).map_err(|e| Error::BadEncoding(e.into_bytes()))
            })
        });
        result
    }

    pub(crate) fn set_password(&self, password: &str) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            // Resolve before calling set_password, which would create a modern
            // entry immediately and shadow an existing legacy data key.
            match self.inner.get_credential() {
                Ok(_) => self.inner.set_password(password),
                Err(Error::NoEntry) => only_if_missing(
                    self.with_legacy_item(|item| {
                        item.set_secret(password.as_bytes(), "text/plain")
                            .map_err(platform_failure)?;
                        Ok(())
                    }),
                    || self.inner.set_password(password),
                ),
                Err(error) => Err(error),
            }
        }
        #[cfg(not(target_os = "linux"))]
        self.inner.set_password(password)
    }

    pub(crate) fn delete_credential(&self) -> Result<()> {
        let result = self.inner.delete_credential();
        #[cfg(target_os = "linux")]
        let result = only_if_missing(result, || {
            self.with_legacy_item(|item| {
                item.delete().map_err(platform_failure)?;
                Ok(())
            })
        });
        result
    }

    #[cfg(target_os = "linux")]
    fn with_legacy_item<T>(
        &self,
        operation: impl FnOnce(&dbus_secret_service::Item<'_>) -> Result<T>,
    ) -> Result<T> {
        use dbus_secret_service::{EncryptionType, SecretService};
        use std::collections::HashMap;

        // As in keyring 3.6.3: only after zero target=default matches, search
        // service+username in the default collection, omitting target. This
        // deliberately preserves the old implementation (which does not filter
        // out target-bearing items in that collection). Never search all stores
        // without a target, or treat access/ambiguity errors as absence.
        let service = SecretService::connect(EncryptionType::Dh).map_err(platform_failure)?;
        let collection = service.get_default_collection().map_err(platform_failure)?;
        let items = collection
            .search_items(HashMap::from([
                ("service", self.service.as_str()),
                ("username", self.user.as_str()),
            ]))
            .map_err(platform_failure)?;
        match items.as_slice() {
            [] => Err(Error::NoEntry),
            [item] => operation(item),
            _ => Err(Error::PlatformFailure(Box::new(std::io::Error::other(
                "Multiple matching legacy Secret Service items; refusing to choose one",
            )))),
        }
    }
}

#[cfg(target_os = "linux")]
fn platform_failure(error: dbus_secret_service::Error) -> Error {
    Error::PlatformFailure(Box::new(error))
}

#[cfg(any(target_os = "linux", test))]
fn only_if_missing<T>(result: Result<T>, fallback: impl FnOnce() -> Result<T>) -> Result<T> {
    match result {
        Err(Error::NoEntry) => fallback(),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_only_runs_for_missing_credentials() {
        assert_eq!(only_if_missing(Err(Error::NoEntry), || Ok(7)).unwrap(), 7);
        assert_eq!(
            only_if_missing(Ok(3), || panic!("must not fall back")).unwrap(),
            3
        );
        for error in [
            Error::Ambiguous(Vec::new()),
            Error::BadEncoding(vec![255]),
            Error::NoStorageAccess(Box::new(std::io::Error::other("locked"))),
        ] {
            assert!(only_if_missing::<()>(Err(error), || panic!("must not fall back")).is_err());
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn unsupported_platform_entries_do_not_gain_persistent_storage() {
        let entry = Entry::new("zentra-test-mock", "api_key").unwrap();
        entry.set_password("synthetic").unwrap();
        assert_eq!(entry.get_password().unwrap(), "synthetic");
        assert!(matches!(
            Entry::new("zentra-test-mock", "api_key")
                .unwrap()
                .get_password(),
            Err(Error::NoEntry)
        ));
        entry.delete_credential().unwrap();
        assert!(matches!(entry.get_password(), Err(Error::NoEntry)));
    }
}
