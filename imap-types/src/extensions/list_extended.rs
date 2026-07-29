//! IMAP LIST Command Extensions.
//!
//! See [RFC 5258](https://www.rfc-editor.org/rfc/rfc5258).
//!
//! This module provides the extended `LIST` command's *selection options* and
//! *return options*, and the extended data items (`CHILDINFO`, and generic
//! vendor/standard items) returned in `LIST` responses. The new mailbox
//! attributes (`\Subscribed`, `\Remote`, `\HasChildren`, `\HasNoChildren`,
//! `\NonExistent`) are added to
//! [`FlagNameAttribute`](crate::flag::FlagNameAttribute).
//!
//! The parenthesized *patterns* form of `mbox-or-pat`
//! (e.g., `LIST "" ("foo" "bar")`) is supported via
//! [`MboxOrPat`](crate::mailbox::MboxOrPat).
//!
//! # Not (yet) supported
//!
//! * The bare (unparenthesized) `tagged-ext-simple` form of `tagged-ext-val`
//!   (a `sequence-set` or `number` value). Only the parenthesized
//!   `"(" [tagged-ext-comp] ")"` form is supported. This is what all
//!   real-world extensions (`CHILDINFO`, `OLDNAME`, `STATUS`, ...) use.

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use bounded_static_derive::ToStatic;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "arbitrary")]
use crate::arbitrary::impl_arbitrary_try_from;
use crate::{
    core::{AString, Atom, Vec1},
    extensions::list_extended::error::{MboxListExtendedItemTagError, OptionExtensionTagError},
};

/// A selection option of the extended `LIST` command (`list-select-opt`).
///
/// Selection options determine which mailbox names are selected by `LIST`.
///
/// ```abnf
/// list-select-opt = list-select-base-opt / list-select-independent-opt
///                   / list-select-mod-opt
/// list-select-base-opt = "SUBSCRIBED" / option-extension
/// list-select-independent-opt = "REMOTE" / option-extension
/// list-select-mod-opt = "RECURSIVEMATCH" / option-extension
/// ```
///
/// See [RFC 5258, section 3](https://www.rfc-editor.org/rfc/rfc5258#section-3).
// TODO(misuse): `RECURSIVEMATCH` (a "mod" option) MUST NOT occur without a
//               "base" option such as `SUBSCRIBED`, and the base/independent
//               options can't be combined arbitrarily. This isn't enforced yet.
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "content"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub enum ListSelectOption<'a> {
    /// `SUBSCRIBED`
    ///
    /// Causes the `LIST` command to list subscribed names, not the existing
    /// mailbox names.
    Subscribed,

    /// `REMOTE`
    ///
    /// Causes the `LIST` command to show remote mailboxes as well as local
    /// ones.
    Remote,

    /// `RECURSIVEMATCH`
    ///
    /// Forces the server to return information about parent mailboxes that
    /// don't match other selection options, but have some submailboxes that
    /// do.
    RecursiveMatch,

    /// An `option-extension` (a standard or vendor-specific option).
    Extension(ListSelectOptionExtension<'a>),
}

/// A return option of the extended `LIST` command (`return-option`).
///
/// Return options control what information is returned for each matched
/// mailbox.
///
/// ```abnf
/// return-option = "SUBSCRIBED" / "CHILDREN" / option-extension
/// ```
///
/// See [RFC 5258, section 3](https://www.rfc-editor.org/rfc/rfc5258#section-3).
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "content"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub enum ListReturnOption<'a> {
    /// `SUBSCRIBED`
    ///
    /// Causes the `LIST` command to return subscription state by including the
    /// `\Subscribed` attribute in the returned mailbox attributes.
    Subscribed,

    /// `CHILDREN`
    ///
    /// Requests the child mailbox information (`\HasChildren` /
    /// `\HasNoChildren`) as defined by the CHILDREN extension (RFC 3348).
    Children,

    /// An `option-extension` (a standard or vendor-specific option).
    Extension(ListReturnOptionExtension<'a>),
}

/// A selection `option-extension` for the extended `LIST` command.
///
/// ```abnf
/// option-extension = (option-standard-tag / option-vendor-tag) [SP option-value]
/// option-standard-tag = atom
/// option-vendor-tag = vendor-token "-" atom
/// option-value = "(" option-val-comp ")"
/// ```
///
/// Both `option-standard-tag` and `option-vendor-tag` are syntactically atoms.
///
/// See [RFC 5258, section 3](https://www.rfc-editor.org/rfc/rfc5258#section-3).
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct ListSelectOptionExtension<'a> {
    /// The option tag (`option-standard-tag` / `option-vendor-tag`).
    pub tag: ListSelectOptionExtensionTag<'a>,
    /// The optional `option-value` (`"(" option-val-comp ")"`).
    ///
    /// `None` means the option carries no value.
    pub value: Option<TaggedExtComp<'a>>,
}

/// A return `option-extension` for the extended `LIST` command.
///
/// Same grammar as [`ListSelectOptionExtension`], but its tag reserves the
/// standardized *return* option names instead of the selection ones.
///
/// See [RFC 5258, section 3](https://www.rfc-editor.org/rfc/rfc5258#section-3).
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct ListReturnOptionExtension<'a> {
    /// The option tag (`option-standard-tag` / `option-vendor-tag`).
    pub tag: ListReturnOptionExtensionTag<'a>,
    /// The optional `option-value` (`"(" option-val-comp ")"`).
    ///
    /// `None` means the option carries no value.
    pub value: Option<TaggedExtComp<'a>>,
}

/// The tag of a [`ListSelectOptionExtension`].
///
/// It's guaranteed that this type can't represent any of the standardized
/// *selection* option names (`SUBSCRIBED`, `REMOTE`, `RECURSIVEMATCH`). Note
/// that selection and return options live in distinct namespaces in RFC 5258,
/// so `CHILDREN` (a return option name) is a valid selection extension tag.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "Atom"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct ListSelectOptionExtensionTag<'a>(Atom<'a>);

impl<'a> ListSelectOptionExtensionTag<'a> {
    pub fn validate(atom: &Atom) -> Result<(), OptionExtensionTagError> {
        if matches!(
            atom.as_ref().to_ascii_lowercase().as_str(),
            "subscribed" | "remote" | "recursivematch"
        ) {
            return Err(OptionExtensionTagError::Reserved);
        }

        Ok(())
    }

    pub fn inner(&self) -> &Atom<'a> {
        &self.0
    }

    /// Constructs an option-extension tag without validation.
    ///
    /// # Warning: IMAP conformance
    ///
    /// The caller must ensure that `atom` is valid according to
    /// [`Self::validate`]. Failing to do so may create invalid/unparsable IMAP
    /// messages, or even produce unintended protocol flows.
    ///
    /// Note: This method will `panic!` on wrong input in debug builds.
    pub fn unvalidated(atom: Atom<'a>) -> Self {
        #[cfg(debug_assertions)]
        Self::validate(&atom).unwrap();

        Self(atom)
    }
}

impl<'a> TryFrom<Atom<'a>> for ListSelectOptionExtensionTag<'a> {
    type Error = OptionExtensionTagError;

    fn try_from(atom: Atom<'a>) -> Result<Self, Self::Error> {
        Self::validate(&atom)?;

        Ok(Self(atom))
    }
}

/// The tag of a [`ListReturnOptionExtension`].
///
/// It's guaranteed that this type can't represent any of the standardized
/// *return* option names (`SUBSCRIBED`, `CHILDREN`). Note that selection and
/// return options live in distinct namespaces in RFC 5258, so `REMOTE` and
/// `RECURSIVEMATCH` (selection option names) are valid return extension tags.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "Atom"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct ListReturnOptionExtensionTag<'a>(Atom<'a>);

impl<'a> ListReturnOptionExtensionTag<'a> {
    pub fn validate(atom: &Atom) -> Result<(), OptionExtensionTagError> {
        if matches!(
            atom.as_ref().to_ascii_lowercase().as_str(),
            "subscribed" | "children"
        ) {
            return Err(OptionExtensionTagError::Reserved);
        }

        Ok(())
    }

    pub fn inner(&self) -> &Atom<'a> {
        &self.0
    }

    /// Constructs an option-extension tag without validation.
    ///
    /// # Warning: IMAP conformance
    ///
    /// The caller must ensure that `atom` is valid according to
    /// [`Self::validate`]. Failing to do so may create invalid/unparsable IMAP
    /// messages, or even produce unintended protocol flows.
    ///
    /// Note: This method will `panic!` on wrong input in debug builds.
    pub fn unvalidated(atom: Atom<'a>) -> Self {
        #[cfg(debug_assertions)]
        Self::validate(&atom).unwrap();

        Self(atom)
    }
}

impl<'a> TryFrom<Atom<'a>> for ListReturnOptionExtensionTag<'a> {
    type Error = OptionExtensionTagError;

    fn try_from(atom: Atom<'a>) -> Result<Self, Self::Error> {
        Self::validate(&atom)?;

        Ok(Self(atom))
    }
}

/// A generic extended data item value (`tagged-ext-comp`).
///
/// ```abnf
/// tagged-ext-comp = astring /
///                   tagged-ext-comp *(SP tagged-ext-comp) /
///                   "(" tagged-ext-comp ")"
/// ```
///
/// This is modeled as a non-empty, space-separated sequence of items, where
/// each item is either an `astring` or a parenthesized `tagged-ext-comp`. It's
/// the same grammar as `option-val-comp`.
///
/// See [RFC 5258, section 6](https://www.rfc-editor.org/rfc/rfc5258#section-6).
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct TaggedExtComp<'a>(pub Vec1<TaggedExtCompItem<'a>>);

/// A single item of a [`TaggedExtComp`].
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "content"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub enum TaggedExtCompItem<'a> {
    /// An `astring`.
    AString(AString<'a>),
    /// A parenthesized `tagged-ext-comp` (`"(" tagged-ext-comp ")"`).
    Parenthesized(TaggedExtComp<'a>),
}

/// A selection option quoted inside a `CHILDINFO` extended data item
/// (`list-select-base-opt-quoted`).
///
/// ```abnf
/// list-select-base-opt = "SUBSCRIBED" / option-extension
/// ```
///
/// Note: Only the standardized `SUBSCRIBED` option is supported here.
///
/// See [RFC 5258, section 3.5](https://www.rfc-editor.org/rfc/rfc5258#section-3.5).
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ToStatic)]
pub enum ChildInfoSelectOption {
    /// `"SUBSCRIBED"`
    ///
    /// At least one subscribed submailbox (via the `SUBSCRIBED` selection
    /// option) is present below the returned mailbox.
    Subscribed,
}

/// An extended data item of a `LIST` response (`mbox-list-extended-item`).
///
/// ```abnf
/// mbox-list-extended-item = mbox-list-extended-item-tag SP tagged-ext-val
/// childinfo-extended-item = "CHILDINFO" SP "("
///     list-select-base-opt-quoted *(SP list-select-base-opt-quoted) ")"
/// ```
///
/// See [RFC 5258, section 3.5](https://www.rfc-editor.org/rfc/rfc5258#section-3.5).
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", content = "content"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub enum MboxListExtendedItem<'a> {
    /// The `CHILDINFO` extended data item.
    ChildInfo(Vec1<ChildInfoSelectOption>),

    /// A generic (vendor or standard) extended data item.
    Other {
        /// The item tag (`mbox-list-extended-item-tag`).
        tag: MboxListExtendedItemTag<'a>,
        /// The parenthesized item value (`"(" [tagged-ext-comp] ")"`).
        ///
        /// `None` means an empty value (`()`).
        value: Option<TaggedExtComp<'a>>,
    },
}

/// The tag of a generic [`MboxListExtendedItem::Other`].
///
/// It's guaranteed that this type can't represent the `CHILDINFO` item (which
/// has its own [`MboxListExtendedItem::ChildInfo`] variant).
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "AString"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, ToStatic)]
pub struct MboxListExtendedItemTag<'a>(AString<'a>);

impl<'a> MboxListExtendedItemTag<'a> {
    pub fn validate(value: impl AsRef<[u8]>) -> Result<(), MboxListExtendedItemTagError> {
        if value.as_ref().eq_ignore_ascii_case(b"childinfo") {
            return Err(MboxListExtendedItemTagError::Reserved);
        }

        Ok(())
    }

    pub fn inner(&self) -> &AString<'a> {
        &self.0
    }

    /// Constructs an extended-item tag without validation.
    ///
    /// # Warning: IMAP conformance
    ///
    /// The caller must ensure that `value` is valid according to
    /// [`Self::validate`]. Failing to do so may create invalid/unparsable IMAP
    /// messages, or even produce unintended protocol flows.
    ///
    /// Note: This method will `panic!` on wrong input in debug builds.
    pub fn unvalidated(value: AString<'a>) -> Self {
        #[cfg(debug_assertions)]
        Self::validate(&value).unwrap();

        Self(value)
    }
}

impl<'a> TryFrom<AString<'a>> for MboxListExtendedItemTag<'a> {
    type Error = MboxListExtendedItemTagError;

    fn try_from(value: AString<'a>) -> Result<Self, Self::Error> {
        Self::validate(&value)?;

        Ok(Self(value))
    }
}

#[cfg(feature = "arbitrary")]
impl_arbitrary_try_from! { ListSelectOptionExtensionTag<'a>, Atom<'a> }
#[cfg(feature = "arbitrary")]
impl_arbitrary_try_from! { ListReturnOptionExtensionTag<'a>, Atom<'a> }
#[cfg(feature = "arbitrary")]
impl_arbitrary_try_from! { MboxListExtendedItemTag<'a>, AString<'a> }

/// Error-related types.
pub mod error {
    use thiserror::Error;

    #[derive(Clone, Debug, Eq, Error, Hash, Ord, PartialEq, PartialOrd)]
    pub enum OptionExtensionTagError {
        #[error("Reserved: Please use one of the typed selection/return options")]
        Reserved,
    }

    #[derive(Clone, Debug, Eq, Error, Hash, Ord, PartialEq, PartialOrd)]
    pub enum MboxListExtendedItemTagError {
        #[error("Reserved: Please use `MboxListExtendedItem::ChildInfo`")]
        Reserved,
    }
}
