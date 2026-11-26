//! `open_enum!`: an enumeration whose unknown values are kept, not refused.

/// Define an open enumeration: known values as variants, anything else kept
/// in `Other`. It (de)serializes as its string.
///
/// Equality and hashing compare the wire strings, so a value built by hand
/// as `Other("private".into())` is the same value as the `Private` variant;
/// `From<&str>` never builds such an `Other` in the first place.
macro_rules! open_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $( $(#[$vmeta:meta])* $variant:ident = $value:literal, )+
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone)]
        pub enum $name {
            $( $(#[$vmeta])* $variant, )+
            /// A value this version does not know (§2.3). Build values with
            /// `From<&str>`, which never puts a known value here.
            Other(String),
        }

        impl $name {
            /// The value as sent on the wire.
            pub fn as_str(&self) -> &str {
                match self {
                    $( Self::$variant => $value, )+
                    Self::Other(s) => s,
                }
            }

            /// Whether this version knows the value (it is not `Other`, or
            /// is an `Other` spelling a known value).
            pub fn is_known(&self) -> bool {
                !matches!(Self::from(self.as_str()), Self::Other(_))
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                match s {
                    $( $value => Self::$variant, )+
                    other => Self::Other(other.to_owned()),
                }
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.as_str() == other.as_str()
            }
        }

        impl Eq for $name {}

        impl core::hash::Hash for $name {
            fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
                self.as_str().hash(state);
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(self.as_str())
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = <std::borrow::Cow<'de, str>>::deserialize(d)?;
                Ok(Self::from(s.as_ref()))
            }
        }
    };
}
pub(crate) use open_enum;

#[cfg(test)]
mod tests {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    use crate::wire::Tier;

    fn hash(t: &Tier) -> u64 {
        let mut h = DefaultHasher::new();
        t.hash(&mut h);
        h.finish()
    }

    #[test]
    fn unknown_values_are_kept() {
        let tier: Tier = serde_json::from_str("\"members-plus\"").unwrap();
        assert_eq!(tier, Tier::Other("members-plus".into()));
        assert!(!tier.is_known());
        assert_eq!(serde_json::to_string(&tier).unwrap(), "\"members-plus\"");
        assert_eq!(Tier::from("private"), Tier::Private);
        assert_eq!(Tier::Discoverable.to_string(), "discoverable");
    }

    #[test]
    fn a_hand_built_other_equals_the_known_variant() {
        let by_hand = Tier::Other("private".into());
        assert_eq!(by_hand, Tier::Private);
        assert_eq!(hash(&by_hand), hash(&Tier::Private));
        assert!(by_hand.is_known());
        assert_ne!(Tier::Other("Private".into()), Tier::Private);
    }
}
