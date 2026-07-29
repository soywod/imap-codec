//! IMAP LIST Command Extensions (RFC 5258).

use abnf_core::streaming::{dquote, sp};
use imap_types::{
    core::Vec1,
    extensions::list_extended::{
        ChildInfoSelectOption, ListReturnOption, ListReturnOptionExtension,
        ListReturnOptionExtensionTag, ListSelectOption, ListSelectOptionExtension,
        ListSelectOptionExtensionTag, MboxListExtendedItem, MboxListExtendedItemTag, TaggedExtComp,
        TaggedExtCompItem,
    },
};
use nom::{
    branch::alt,
    bytes::streaming::{tag, tag_no_case},
    combinator::{map, opt, value},
    error::ErrorKind,
    multi::{separated_list0, separated_list1},
    sequence::{delimited, preceded},
};

use crate::{
    core::{astring, atom},
    decode::{IMAPErrorKind, IMAPParseError, IMAPResult},
};

/// Maximum recursion depth when parsing a `tagged-ext-comp`.
const TAGGED_EXT_COMP_RECURSION_LIMIT: usize = 8;

/// Build a recoverable "this doesn't match" error.
fn reject(input: &[u8]) -> nom::Err<IMAPParseError<'_, &[u8]>> {
    nom::Err::Error(IMAPParseError {
        input,
        kind: IMAPErrorKind::Nom(ErrorKind::Verify),
    })
}

/// ```abnf
/// list-select-opts = "(" [
///      (*(list-select-opt SP) list-select-base-opt *(SP list-select-opt))
///    / (list-select-independent-opt *(SP list-select-independent-opt))
///  ] ")"
/// ```
///
/// Note: The mutual constraints between base/independent/mod options are not
///       enforced; any (possibly empty) list of options is accepted.
pub(crate) fn list_select_opts(input: &[u8]) -> IMAPResult<&[u8], Vec<ListSelectOption>> {
    delimited(tag(b"("), separated_list0(sp, list_select_opt), tag(b")"))(input)
}

/// ```abnf
/// list-select-opt = list-select-base-opt / list-select-independent-opt
///                   / list-select-mod-opt
/// list-select-base-opt = "SUBSCRIBED" / option-extension
/// list-select-independent-opt = "REMOTE" / option-extension
/// list-select-mod-opt = "RECURSIVEMATCH" / option-extension
/// ```
pub(crate) fn list_select_opt(input: &[u8]) -> IMAPResult<&[u8], ListSelectOption> {
    let (remaining, atom) = atom(input)?;

    match atom.as_ref().to_ascii_lowercase().as_str() {
        "subscribed" => Ok((remaining, ListSelectOption::Subscribed)),
        "remote" => Ok((remaining, ListSelectOption::Remote)),
        "recursivematch" => Ok((remaining, ListSelectOption::RecursiveMatch)),
        _ => {
            let tag = ListSelectOptionExtensionTag::try_from(atom).map_err(|_| reject(input))?;
            let (remaining, value) = opt(preceded(sp, option_value))(remaining)?;

            Ok((
                remaining,
                ListSelectOption::Extension(ListSelectOptionExtension { tag, value }),
            ))
        }
    }
}

/// ```abnf
/// list-return-opts = "RETURN" SP "(" [return-option *(SP return-option)] ")"
/// ```
pub(crate) fn list_return_opts(input: &[u8]) -> IMAPResult<&[u8], Vec<ListReturnOption>> {
    preceded(
        tag_no_case(b"RETURN "),
        delimited(tag(b"("), separated_list0(sp, return_option), tag(b")")),
    )(input)
}

/// ```abnf
/// return-option = "SUBSCRIBED" / "CHILDREN" / option-extension
/// ```
pub(crate) fn return_option(input: &[u8]) -> IMAPResult<&[u8], ListReturnOption> {
    let (remaining, atom) = atom(input)?;

    match atom.as_ref().to_ascii_lowercase().as_str() {
        "subscribed" => Ok((remaining, ListReturnOption::Subscribed)),
        "children" => Ok((remaining, ListReturnOption::Children)),
        _ => {
            let tag = ListReturnOptionExtensionTag::try_from(atom).map_err(|_| reject(input))?;
            let (remaining, value) = opt(preceded(sp, option_value))(remaining)?;

            Ok((
                remaining,
                ListReturnOption::Extension(ListReturnOptionExtension { tag, value }),
            ))
        }
    }
}

/// ```abnf
/// option-value = "(" option-val-comp ")"
/// option-val-comp = tagged-ext-comp
/// ```
pub(crate) fn option_value(input: &[u8]) -> IMAPResult<&[u8], TaggedExtComp> {
    delimited(
        tag(b"("),
        |input| tagged_ext_comp(input, TAGGED_EXT_COMP_RECURSION_LIMIT),
        tag(b")"),
    )(input)
}

/// ```abnf
/// tagged-ext-comp = astring /
///                   tagged-ext-comp *(SP tagged-ext-comp) /
///                   "(" tagged-ext-comp ")"
/// ```
///
/// Modeled as a non-empty, space-separated sequence of items.
pub(crate) fn tagged_ext_comp(input: &[u8], depth: usize) -> IMAPResult<&[u8], TaggedExtComp> {
    if depth == 0 {
        return Err(nom::Err::Failure(IMAPParseError {
            input,
            kind: IMAPErrorKind::RecursionLimitExceeded,
        }));
    }

    map(
        separated_list1(sp, move |input| tagged_ext_comp_item(input, depth)),
        |items| TaggedExtComp(Vec1::unvalidated(items)),
    )(input)
}

/// A single item of a `tagged-ext-comp` (`astring` or `"(" tagged-ext-comp ")"`).
fn tagged_ext_comp_item(input: &[u8], depth: usize) -> IMAPResult<&[u8], TaggedExtCompItem> {
    alt((
        map(astring, TaggedExtCompItem::AString),
        map(
            delimited(
                tag(b"("),
                move |input| tagged_ext_comp(input, depth - 1),
                tag(b")"),
            ),
            TaggedExtCompItem::Parenthesized,
        ),
    ))(input)
}

/// `[SP mbox-list-extended]`
///
/// The optional extended data at the end of a `mailbox-list` in a `LIST`
/// response.
pub(crate) fn list_extended_suffix(input: &[u8]) -> IMAPResult<&[u8], Vec<MboxListExtendedItem>> {
    map(opt(preceded(sp, mbox_list_extended)), |maybe| {
        maybe.unwrap_or_default()
    })(input)
}

/// ```abnf
/// mbox-list-extended = "(" [mbox-list-extended-item
///                       *(SP mbox-list-extended-item)] ")"
/// ```
pub(crate) fn mbox_list_extended(input: &[u8]) -> IMAPResult<&[u8], Vec<MboxListExtendedItem>> {
    delimited(
        tag(b"("),
        separated_list0(sp, mbox_list_extended_item),
        tag(b")"),
    )(input)
}

/// ```abnf
/// mbox-list-extended-item = mbox-list-extended-item-tag SP tagged-ext-val
/// ```
///
/// Where `childinfo-extended-item` is recognized specially.
pub(crate) fn mbox_list_extended_item(input: &[u8]) -> IMAPResult<&[u8], MboxListExtendedItem> {
    alt((
        map(childinfo_extended_item, MboxListExtendedItem::ChildInfo),
        mbox_list_extended_item_other,
    ))(input)
}

/// A generic `mbox-list-extended-item` (`tag SP "(" [tagged-ext-comp] ")"`).
///
/// Note: Only the parenthesized `tagged-ext-val` form is supported (not the
///       bare `tagged-ext-simple` form).
fn mbox_list_extended_item_other(input: &[u8]) -> IMAPResult<&[u8], MboxListExtendedItem> {
    let (remaining, item_tag) = astring(input)?;
    let item_tag = MboxListExtendedItemTag::try_from(item_tag).map_err(|_| reject(input))?;

    let (remaining, value) = preceded(
        sp,
        delimited(
            tag(b"("),
            opt(|input| tagged_ext_comp(input, TAGGED_EXT_COMP_RECURSION_LIMIT)),
            tag(b")"),
        ),
    )(remaining)?;

    Ok((
        remaining,
        MboxListExtendedItem::Other {
            tag: item_tag,
            value,
        },
    ))
}

/// ```abnf
/// childinfo-extended-item = "CHILDINFO" SP "("
///     list-select-base-opt-quoted *(SP list-select-base-opt-quoted) ")"
/// ```
pub(crate) fn childinfo_extended_item(
    input: &[u8],
) -> IMAPResult<&[u8], Vec1<ChildInfoSelectOption>> {
    map(
        preceded(
            tag_no_case(b"CHILDINFO "),
            delimited(
                tag(b"("),
                separated_list1(sp, list_select_base_opt_quoted),
                tag(b")"),
            ),
        ),
        Vec1::unvalidated,
    )(input)
}

/// ```abnf
/// list-select-base-opt-quoted = DQUOTE list-select-base-opt DQUOTE
/// list-select-base-opt = "SUBSCRIBED" / option-extension
/// ```
///
/// Note: Only the standardized `SUBSCRIBED` option is supported here.
pub(crate) fn list_select_base_opt_quoted(
    input: &[u8],
) -> IMAPResult<&[u8], ChildInfoSelectOption> {
    delimited(
        dquote,
        value(
            ChildInfoSelectOption::Subscribed,
            tag_no_case(b"SUBSCRIBED"),
        ),
        dquote,
    )(input)
}

#[cfg(test)]
mod tests {
    use imap_types::{
        command::{Command, CommandBody},
        core::{AString, QuotedChar, Vec1},
        extensions::list_extended::{
            ChildInfoSelectOption, ListReturnOption, ListReturnOptionExtension,
            ListReturnOptionExtensionTag, ListSelectOption, ListSelectOptionExtension,
            ListSelectOptionExtensionTag, MboxListExtendedItem, MboxListExtendedItemTag,
            TaggedExtComp, TaggedExtCompItem,
        },
        flag::FlagNameAttribute,
        response::{Capability, Code, Data, Greeting, Response},
    };

    use crate::testing::{kat_inverse_command, kat_inverse_greeting, kat_inverse_response};

    fn astr(s: &str) -> AString<'static> {
        AString::try_from(s.to_string()).unwrap()
    }

    fn comp(items: &[&str]) -> TaggedExtComp<'static> {
        TaggedExtComp(
            Vec1::try_from(
                items
                    .iter()
                    .map(|s| TaggedExtCompItem::AString(astr(s)))
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
        )
    }

    #[test]
    fn test_kat_inverse_command_list_extended() {
        kat_inverse_command(&[
            // Plain LIST still round-trips.
            (
                b"A LIST \"\" *\r\n".as_ref(),
                b"".as_ref(),
                Command::new("A", CommandBody::list("", "*").unwrap()).unwrap(),
            ),
            // Named selection and return options.
            (
                b"A LIST (SUBSCRIBED REMOTE) \"\" % RETURN (SUBSCRIBED CHILDREN)\r\n".as_ref(),
                b"".as_ref(),
                Command::new(
                    "A",
                    CommandBody::List {
                        selection_options: vec![
                            ListSelectOption::Subscribed,
                            ListSelectOption::Remote,
                        ],
                        reference: "".try_into().unwrap(),
                        mailbox_wildcard: "%".try_into().unwrap(),
                        return_options: vec![
                            ListReturnOption::Subscribed,
                            ListReturnOption::Children,
                        ],
                    },
                )
                .unwrap(),
            ),
            // option-extension with a value (selection option).
            (
                b"A LIST (SUBSCRIBED VENDOR.X-FOO (a b)) \"\" *\r\n".as_ref(),
                b"".as_ref(),
                Command::new(
                    "A",
                    CommandBody::List {
                        selection_options: vec![
                            ListSelectOption::Subscribed,
                            ListSelectOption::Extension(ListSelectOptionExtension {
                                tag: ListSelectOptionExtensionTag::try_from(
                                    imap_types::core::Atom::try_from("VENDOR.X-FOO").unwrap(),
                                )
                                .unwrap(),
                                value: Some(comp(&["a", "b"])),
                            }),
                        ],
                        reference: "".try_into().unwrap(),
                        mailbox_wildcard: "*".try_into().unwrap(),
                        return_options: vec![],
                    },
                )
                .unwrap(),
            ),
            // Distinct namespaces: `CHILDREN` is a return keyword, so it's a
            // valid *selection* option-extension. `REMOTE` is a selection
            // keyword, so it's a valid *return* option-extension.
            (
                b"A LIST (CHILDREN) \"\" * RETURN (REMOTE)\r\n".as_ref(),
                b"".as_ref(),
                Command::new(
                    "A",
                    CommandBody::List {
                        selection_options: vec![ListSelectOption::Extension(
                            ListSelectOptionExtension {
                                tag: ListSelectOptionExtensionTag::try_from(
                                    imap_types::core::Atom::try_from("CHILDREN").unwrap(),
                                )
                                .unwrap(),
                                value: None,
                            },
                        )],
                        reference: "".try_into().unwrap(),
                        mailbox_wildcard: "*".try_into().unwrap(),
                        return_options: vec![ListReturnOption::Extension(
                            ListReturnOptionExtension {
                                tag: ListReturnOptionExtensionTag::try_from(
                                    imap_types::core::Atom::try_from("REMOTE").unwrap(),
                                )
                                .unwrap(),
                                value: None,
                            },
                        )],
                    },
                )
                .unwrap(),
            ),
            // option-extension without a value (return option) + nested comp.
            (
                b"A LIST \"\" * RETURN (X-EXT ((a b) c))\r\n".as_ref(),
                b"".as_ref(),
                Command::new(
                    "A",
                    CommandBody::List {
                        selection_options: vec![],
                        reference: "".try_into().unwrap(),
                        mailbox_wildcard: "*".try_into().unwrap(),
                        return_options: vec![ListReturnOption::Extension(
                            ListReturnOptionExtension {
                                tag: ListReturnOptionExtensionTag::try_from(
                                    imap_types::core::Atom::try_from("X-EXT").unwrap(),
                                )
                                .unwrap(),
                                value: Some(TaggedExtComp(
                                    Vec1::try_from(vec![
                                        TaggedExtCompItem::Parenthesized(comp(&["a", "b"])),
                                        TaggedExtCompItem::AString(astr("c")),
                                    ])
                                    .unwrap(),
                                )),
                            },
                        )],
                    },
                )
                .unwrap(),
            ),
        ]);
    }

    #[test]
    fn test_kat_inverse_response_list_extended() {
        kat_inverse_response(&[
            // New mailbox attributes.
            (
                b"* LIST (\\HasChildren \\Subscribed) \"/\" foo\r\n".as_ref(),
                b"".as_ref(),
                Response::Data(Data::List {
                    items: vec![
                        FlagNameAttribute::HasChildren,
                        FlagNameAttribute::Subscribed,
                    ],
                    delimiter: Some(QuotedChar::try_from('/').unwrap()),
                    mailbox: "foo".try_into().unwrap(),
                    extended_items: vec![],
                }),
            ),
            // CHILDINFO extended data item.
            (
                b"* LIST (\\Subscribed) \"/\" foo (CHILDINFO (\"SUBSCRIBED\"))\r\n".as_ref(),
                b"".as_ref(),
                Response::Data(Data::List {
                    items: vec![FlagNameAttribute::Subscribed],
                    delimiter: Some(QuotedChar::try_from('/').unwrap()),
                    mailbox: "foo".try_into().unwrap(),
                    extended_items: vec![MboxListExtendedItem::ChildInfo(Vec1::from(
                        ChildInfoSelectOption::Subscribed,
                    ))],
                }),
            ),
            // Generic extended data item (e.g., OLDNAME).
            (
                b"* LIST () \"/\" foo (OLDNAME (bar))\r\n".as_ref(),
                b"".as_ref(),
                Response::Data(Data::List {
                    items: vec![],
                    delimiter: Some(QuotedChar::try_from('/').unwrap()),
                    mailbox: "foo".try_into().unwrap(),
                    extended_items: vec![MboxListExtendedItem::Other {
                        tag: MboxListExtendedItemTag::try_from(astr("OLDNAME")).unwrap(),
                        value: Some(comp(&["bar"])),
                    }],
                }),
            ),
        ]);
    }

    #[test]
    fn test_kat_inverse_greeting_capability_list_extended() {
        kat_inverse_greeting(&[(
            b"* OK [CAPABILITY LIST-EXTENDED] ...\r\n".as_ref(),
            b"".as_ref(),
            Greeting::ok(
                Some(Code::Capability(Vec1::from(Capability::ListExtended))),
                "...",
            )
            .unwrap(),
        )]);
    }

    /// Extended `LIST` commands taken from the examples in
    /// [RFC 5258, section 5](https://www.rfc-editor.org/rfc/rfc5258#section-5).
    ///
    /// Note: The single-pattern (`mbox-or-pat = list-mailbox`) form is used
    /// here; the parenthesized `patterns` form (e.g., example 7) is not yet
    /// supported. Wildcards/mailboxes are given unquoted (their canonical
    /// encoding), which is semantically identical to the quoted forms shown in
    /// the RFC.
    #[test]
    fn test_kat_inverse_command_list_extended_rfc5258_examples() {
        kat_inverse_command(&[
            // Example 2: `A02 LIST (SUBSCRIBED) "" "*"`
            (
                b"A02 LIST (SUBSCRIBED) \"\" *\r\n".as_ref(),
                b"".as_ref(),
                Command::new(
                    "A02",
                    CommandBody::List {
                        selection_options: vec![ListSelectOption::Subscribed],
                        reference: "".try_into().unwrap(),
                        mailbox_wildcard: "*".try_into().unwrap(),
                        return_options: vec![],
                    },
                )
                .unwrap(),
            ),
            // Example 4: `A04 LIST (REMOTE) "" "%" RETURN (CHILDREN)`
            (
                b"A04 LIST (REMOTE) \"\" % RETURN (CHILDREN)\r\n".as_ref(),
                b"".as_ref(),
                Command::new(
                    "A04",
                    CommandBody::List {
                        selection_options: vec![ListSelectOption::Remote],
                        reference: "".try_into().unwrap(),
                        mailbox_wildcard: "%".try_into().unwrap(),
                        return_options: vec![ListReturnOption::Children],
                    },
                )
                .unwrap(),
            ),
            // Example 5: `A05 LIST (REMOTE SUBSCRIBED) "" "*"`
            (
                b"A05 LIST (REMOTE SUBSCRIBED) \"\" *\r\n".as_ref(),
                b"".as_ref(),
                Command::new(
                    "A05",
                    CommandBody::List {
                        selection_options: vec![
                            ListSelectOption::Remote,
                            ListSelectOption::Subscribed,
                        ],
                        reference: "".try_into().unwrap(),
                        mailbox_wildcard: "*".try_into().unwrap(),
                        return_options: vec![],
                    },
                )
                .unwrap(),
            ),
            // Example 6: `A06 LIST (REMOTE) "" "*" RETURN (SUBSCRIBED)`
            (
                b"A06 LIST (REMOTE) \"\" * RETURN (SUBSCRIBED)\r\n".as_ref(),
                b"".as_ref(),
                Command::new(
                    "A06",
                    CommandBody::List {
                        selection_options: vec![ListSelectOption::Remote],
                        reference: "".try_into().unwrap(),
                        mailbox_wildcard: "*".try_into().unwrap(),
                        return_options: vec![ListReturnOption::Subscribed],
                    },
                )
                .unwrap(),
            ),
            // Example 8C / 10 (a3): `LIST (SUBSCRIBED RECURSIVEMATCH) "" "%" RETURN (CHILDREN)`
            (
                b"C04 LIST (SUBSCRIBED RECURSIVEMATCH) \"\" % RETURN (CHILDREN)\r\n".as_ref(),
                b"".as_ref(),
                Command::new(
                    "C04",
                    CommandBody::List {
                        selection_options: vec![
                            ListSelectOption::Subscribed,
                            ListSelectOption::RecursiveMatch,
                        ],
                        reference: "".try_into().unwrap(),
                        mailbox_wildcard: "%".try_into().unwrap(),
                        return_options: vec![ListReturnOption::Children],
                    },
                )
                .unwrap(),
            ),
        ]);
    }

    /// Extended `LIST` responses taken from the examples in
    /// [RFC 5258, section 5](https://www.rfc-editor.org/rfc/rfc5258#section-5).
    ///
    /// Note: Mailbox names are given unquoted (their canonical encoding), and
    /// `CHILDINFO` is unquoted per the `childinfo-extended-item` ABNF (only the
    /// inner `list-select-base-opt-quoted` is `DQUOTE`-wrapped).
    #[test]
    fn test_kat_inverse_response_list_extended_rfc5258_examples() {
        kat_inverse_response(&[
            // Example 1: `* LIST (\Marked \NoInferiors) "/" "inbox"`
            (
                b"* LIST (\\Marked \\NoInferiors) \"/\" inbox\r\n".as_ref(),
                b"".as_ref(),
                Response::Data(Data::List {
                    items: vec![FlagNameAttribute::Marked, FlagNameAttribute::Noinferiors],
                    delimiter: Some(QuotedChar::try_from('/').unwrap()),
                    mailbox: "inbox".try_into().unwrap(),
                    extended_items: vec![],
                }),
            ),
            // Example 2: `* LIST (\Subscribed \NonExistent) "/" "Fruit/Peach"`
            (
                b"* LIST (\\Subscribed \\NonExistent) \"/\" Fruit/Peach\r\n".as_ref(),
                b"".as_ref(),
                Response::Data(Data::List {
                    items: vec![
                        FlagNameAttribute::Subscribed,
                        FlagNameAttribute::NonExistent,
                    ],
                    delimiter: Some(QuotedChar::try_from('/').unwrap()),
                    mailbox: "Fruit/Peach".try_into().unwrap(),
                    extended_items: vec![],
                }),
            ),
            // Example 3: `* LIST (\HasNoChildren) "/" "Tofu"`
            (
                b"* LIST (\\HasNoChildren) \"/\" Tofu\r\n".as_ref(),
                b"".as_ref(),
                Response::Data(Data::List {
                    items: vec![FlagNameAttribute::HasNoChildren],
                    delimiter: Some(QuotedChar::try_from('/').unwrap()),
                    mailbox: "Tofu".try_into().unwrap(),
                    extended_items: vec![],
                }),
            ),
            // Example 4: `* LIST (\HasChildren \Remote) "/" "Meat"`
            (
                b"* LIST (\\HasChildren \\Remote) \"/\" Meat\r\n".as_ref(),
                b"".as_ref(),
                Response::Data(Data::List {
                    items: vec![FlagNameAttribute::HasChildren, FlagNameAttribute::Remote],
                    delimiter: Some(QuotedChar::try_from('/').unwrap()),
                    mailbox: "Meat".try_into().unwrap(),
                    extended_items: vec![],
                }),
            ),
            // Example 11: `* LIST (\NonExistent \HasChildren) "/" music`
            (
                b"* LIST (\\NonExistent \\HasChildren) \"/\" music\r\n".as_ref(),
                b"".as_ref(),
                Response::Data(Data::List {
                    items: vec![
                        FlagNameAttribute::NonExistent,
                        FlagNameAttribute::HasChildren,
                    ],
                    delimiter: Some(QuotedChar::try_from('/').unwrap()),
                    mailbox: "music".try_into().unwrap(),
                    extended_items: vec![],
                }),
            ),
            // Example 9 (D03): `* LIST (\Subscribed) "/" eps2 ("CHILDINFO" ("SUBSCRIBED"))`
            (
                b"* LIST (\\Subscribed) \"/\" eps2 (CHILDINFO (\"SUBSCRIBED\"))\r\n".as_ref(),
                b"".as_ref(),
                Response::Data(Data::List {
                    items: vec![FlagNameAttribute::Subscribed],
                    delimiter: Some(QuotedChar::try_from('/').unwrap()),
                    mailbox: "eps2".try_into().unwrap(),
                    extended_items: vec![MboxListExtendedItem::ChildInfo(Vec1::from(
                        ChildInfoSelectOption::Subscribed,
                    ))],
                }),
            ),
        ]);
    }
}
