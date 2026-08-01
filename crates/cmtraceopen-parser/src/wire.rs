//! Crate-internal helpers for defining tolerant wire-format types.
//!
//! Public capture schemas in this crate have to survive adapters that emit
//! values we have never seen. The helpers here are the single source of that
//! tolerance so every schema module behaves identically.

/// Define a string enum that preserves unrecognized wire values losslessly.
///
/// The generated enum gains an `Unknown(String)` variant. Deserialization maps
/// any unrecognized string into `Unknown`, and serialization writes the raw
/// string back out unchanged, so a round trip never silently drops or rewrites
/// a value produced by a newer adapter.
///
/// The expansion refers to `serde` through absolute paths, so a caller only
/// needs the macro itself in scope.
macro_rules! raw_preserving_string_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $($variant:ident => $wire_value:literal),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum $name {
            $($variant,)+
            Unknown(String),
        }

        impl ::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> ::core::result::Result<S::Ok, S::Error>
            where
                S: ::serde::Serializer,
            {
                let value = match self {
                    $(Self::$variant => $wire_value,)+
                    Self::Unknown(raw) => raw.as_str(),
                };

                serializer.serialize_str(value)
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> ::core::result::Result<Self, D::Error>
            where
                D: ::serde::Deserializer<'de>,
            {
                let raw = <::std::string::String as ::serde::Deserialize>::deserialize(deserializer)?;
                Ok(match raw.as_str() {
                    $($wire_value => Self::$variant,)+
                    _ => Self::Unknown(raw),
                })
            }
        }
    };
}

pub(crate) use raw_preserving_string_enum;
