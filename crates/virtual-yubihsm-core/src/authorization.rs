use crate::{Capability, CapabilitySet, DeviceError, ObjectInfo, ObjectRecord, Result};

/// Immutable authorization snapshot attached to an established secure session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionAuthorization {
    pub authentication_key_id: u16,
    pub capabilities: CapabilitySet,
    pub delegated_capabilities: CapabilitySet,
    pub domains: u16,
}

impl SessionAuthorization {
    pub fn require_capability(self, capability: Capability) -> Result<()> {
        if self.capabilities.contains(capability) {
            Ok(())
        } else {
            Err(DeviceError::InsufficientPermissions)
        }
    }

    pub fn can_see(self, object: &ObjectInfo) -> bool {
        self.domains & object.domains != 0
    }

    pub fn require_visible(self, object: &ObjectInfo) -> Result<()> {
        if self.can_see(object) {
            Ok(())
        } else {
            // A cross-domain object is indistinguishable from a missing object.
            Err(DeviceError::ObjectNotFound)
        }
    }

    pub fn authorize_use(
        self,
        object: &ObjectInfo,
        session_capability: Capability,
        object_capability: Capability,
    ) -> Result<()> {
        self.require_visible(object)?;
        self.require_capability(session_capability)?;
        if object.capabilities.contains(object_capability) {
            Ok(())
        } else {
            Err(DeviceError::InsufficientPermissions)
        }
    }

    pub fn authorize_create(
        self,
        requested: &ObjectInfo,
        command_capability: Capability,
    ) -> Result<()> {
        self.require_capability(command_capability)?;
        requested.validate()?;
        if requested.domains & !self.domains != 0
            || !requested
                .capabilities
                .is_subset_of(self.delegated_capabilities)
            || !requested
                .delegated_capabilities
                .is_subset_of(self.delegated_capabilities)
        {
            return Err(DeviceError::InsufficientPermissions);
        }
        Ok(())
    }

    pub fn authorize_delete(self, object: &ObjectInfo) -> Result<()> {
        let capability = object.object_type.deletion_capability();
        self.require_visible(object)?;
        self.require_capability(capability)
    }

    pub fn authorize_wrapped_export(
        self,
        object: &ObjectRecord,
        wrap_key: &ObjectRecord,
    ) -> Result<()> {
        self.authorize_use(
            &wrap_key.info,
            Capability::ExportWrapped,
            Capability::ExportWrapped,
        )?;
        self.require_visible(&object.info)?;
        if !object
            .info
            .capabilities
            .contains(Capability::ExportableUnderWrap)
            || !object
                .info
                .capabilities
                .is_subset_of(wrap_key.info.delegated_capabilities)
        {
            return Err(DeviceError::InsufficientPermissions);
        }
        Ok(())
    }

    pub fn authorize_wrapped_creation(
        self,
        requested: &ObjectInfo,
        wrap_key: &ObjectRecord,
    ) -> Result<()> {
        self.authorize_create(requested, Capability::ImportWrapped)?;
        if !requested
            .capabilities
            .is_subset_of(wrap_key.info.delegated_capabilities)
        {
            return Err(DeviceError::InsufficientPermissions);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ObjectMaterial, ObjectType};

    fn info(domains: u16, capabilities: CapabilitySet) -> ObjectInfo {
        ObjectInfo {
            capabilities,
            id: 2,
            length: 1,
            domains,
            object_type: ObjectType::Opaque,
            algorithm: 30,
            sequence: 1,
            origin: 1,
            label: b"test".to_vec(),
            delegated_capabilities: CapabilitySet::NONE,
        }
    }

    fn session() -> SessionAuthorization {
        SessionAuthorization {
            authentication_key_id: 1,
            capabilities: CapabilitySet::from_capabilities([
                Capability::PutOpaque,
                Capability::GetOpaque,
            ]),
            delegated_capabilities: CapabilitySet::from_capabilities([Capability::GetOpaque]),
            domains: 0b0011,
        }
    }

    #[test]
    fn existing_object_use_requires_session_object_and_domain_permissions() {
        let allowed = info(
            0b0010,
            CapabilitySet::from_capabilities([Capability::GetOpaque]),
        );
        session()
            .authorize_use(&allowed, Capability::GetOpaque, Capability::GetOpaque)
            .unwrap();

        let hidden = info(0b0100, allowed.capabilities);
        assert_eq!(
            session().authorize_use(&hidden, Capability::GetOpaque, Capability::GetOpaque),
            Err(DeviceError::ObjectNotFound)
        );

        let unusable = info(0b0001, CapabilitySet::NONE);
        assert_eq!(
            session().authorize_use(&unusable, Capability::GetOpaque, Capability::GetOpaque),
            Err(DeviceError::InsufficientPermissions)
        );
    }

    #[test]
    fn creation_is_bounded_by_session_domains_and_delegated_capabilities() {
        let allowed = info(
            0b0011,
            CapabilitySet::from_capabilities([Capability::GetOpaque]),
        );
        session()
            .authorize_create(&allowed, Capability::PutOpaque)
            .unwrap();

        let too_many_domains = info(0b0101, allowed.capabilities);
        assert_eq!(
            session().authorize_create(&too_many_domains, Capability::PutOpaque),
            Err(DeviceError::InsufficientPermissions)
        );

        let too_many_capabilities = info(
            0b0001,
            CapabilitySet::from_capabilities([Capability::GetOpaque, Capability::SignEcdsa]),
        );
        assert_eq!(
            session().authorize_create(&too_many_capabilities, Capability::PutOpaque),
            Err(DeviceError::InsufficientPermissions)
        );
    }

    #[test]
    fn deletion_requires_session_capability_and_domain_but_not_object_capability() {
        let object = info(0b0010, CapabilitySet::NONE);
        let authorized = SessionAuthorization {
            capabilities: CapabilitySet::from_capabilities([Capability::DeleteOpaque]),
            ..session()
        };
        authorized.authorize_delete(&object).unwrap();

        assert_eq!(
            session().authorize_delete(&object),
            Err(DeviceError::InsufficientPermissions)
        );

        let hidden = info(0b0100, CapabilitySet::NONE);
        assert_eq!(
            authorized.authorize_delete(&hidden),
            Err(DeviceError::ObjectNotFound)
        );
    }

    #[test]
    fn wrapping_applies_both_delegated_capability_ceiling_and_domains() {
        let object = ObjectRecord {
            info: info(
                1,
                CapabilitySet::from_capabilities([
                    Capability::GetOpaque,
                    Capability::ExportableUnderWrap,
                ]),
            ),
            material: ObjectMaterial::Opaque(vec![1]),
        };
        let wrap_key = ObjectRecord {
            info: ObjectInfo {
                capabilities: CapabilitySet::from_capabilities([Capability::ExportWrapped]),
                delegated_capabilities: object.info.capabilities,
                object_type: ObjectType::WrapKey,
                ..info(1, CapabilitySet::NONE)
            },
            material: ObjectMaterial::Secret(vec![1]),
        };
        let auth = SessionAuthorization {
            capabilities: CapabilitySet::from_capabilities([Capability::ExportWrapped]),
            ..session()
        };
        auth.authorize_wrapped_export(&object, &wrap_key).unwrap();
    }
}
