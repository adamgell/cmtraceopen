//! Small JSON preflight helpers for strict SCCM contracts.
//!
//! `serde_json::Value` intentionally keeps the last value for duplicate object
//! keys. These helpers preserve field order and repeats so callers can reject
//! ambiguous documents before deserializing their typed wire format.

use std::fmt;

use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

#[derive(Debug)]
pub(crate) enum PreservedJsonValue {
    Unsigned(u64),
    String(String),
    Array(Vec<Self>),
    Object(Vec<(String, Self)>),
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JsonContractPreflightError {
    Malformed,
    DuplicateKey,
}

struct PreservedJsonValueVisitor;

impl<'de> Visitor<'de> for PreservedJsonValueVisitor {
    type Value = PreservedJsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("any JSON value while preserving duplicate object keys")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(PreservedJsonValue::Other)
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(PreservedJsonValue::Other)
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(PreservedJsonValue::Unsigned(value))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(PreservedJsonValue::Other)
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(PreservedJsonValue::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(PreservedJsonValue::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(PreservedJsonValue::Other)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(PreservedJsonValue::Other)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(Self)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element()? {
            values.push(value);
        }
        Ok(PreservedJsonValue::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut fields = Vec::new();
        while let Some(name) = map.next_key()? {
            fields.push((name, map.next_value()?));
        }
        Ok(PreservedJsonValue::Object(fields))
    }
}

impl<'de> Deserialize<'de> for PreservedJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(PreservedJsonValueVisitor)
    }
}

pub(crate) fn parse_preserved_json(
    input: &str,
) -> Result<PreservedJsonValue, JsonContractPreflightError> {
    serde_json::from_str(input).map_err(|_| JsonContractPreflightError::Malformed)
}

pub(crate) fn object_fields(value: &PreservedJsonValue) -> Option<&[(String, PreservedJsonValue)]> {
    let PreservedJsonValue::Object(fields) = value else {
        return None;
    };
    Some(fields)
}

pub(crate) fn field<'a>(
    object: &'a [(String, PreservedJsonValue)],
    name: &str,
) -> Option<&'a PreservedJsonValue> {
    object
        .iter()
        .find_map(|(field, value)| (field == name).then_some(value))
}

pub(crate) fn has_duplicate_object_keys(value: &PreservedJsonValue) -> bool {
    match value {
        PreservedJsonValue::Object(fields) => {
            let mut names = std::collections::BTreeSet::new();
            fields.iter().any(|(name, value)| {
                !names.insert(name.as_str()) || has_duplicate_object_keys(value)
            })
        }
        PreservedJsonValue::Array(values) => values.iter().any(has_duplicate_object_keys),
        _ => false,
    }
}
