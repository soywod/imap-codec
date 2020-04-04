use crate::{
    parse::{core::nz_number, header::header_list, sp},
    types::data_items::{PartSpecifier, Section},
};
use nom::{
    branch::alt,
    bytes::streaming::tag_no_case,
    combinator::{map, opt, value},
    multi::separated_nonempty_list,
    sequence::tuple,
    IResult,
};

/// section = "[" [section-spec] "]"
pub fn section(input: &[u8]) -> IResult<&[u8], Option<Section>> {
    let parser = tuple((tag_no_case(b"["), opt(section_spec), tag_no_case(b"]")));

    let (remaining, (_, section_spec, _)) = parser(input)?;

    Ok((remaining, section_spec))
}

/// section-spec = section-msgtext / (section-part ["." section-text])
pub fn section_spec(input: &[u8]) -> IResult<&[u8], Section> {
    let parser = alt((
        map(section_msgtext, |part_specifier| match part_specifier {
            PartSpecifier::PartNumber(_) => unreachable!(),
            PartSpecifier::Header => Section::Header(None),
            PartSpecifier::HeaderFields(fields) => Section::HeaderFields(None, fields),
            PartSpecifier::HeaderFieldsNot(fields) => Section::HeaderFieldsNot(None, fields),
            PartSpecifier::Text => Section::Text(None),
            PartSpecifier::Mime => unreachable!(),
        }),
        map(
            tuple((section_part, opt(tuple((tag_no_case(b"."), section_text))))),
            |(part_number, maybe_part_specifier)| {
                if let Some((_, part_specifier)) = maybe_part_specifier {
                    match part_specifier {
                        PartSpecifier::PartNumber(_) => unreachable!(),
                        PartSpecifier::Header => Section::Header(Some(part_number)),
                        PartSpecifier::HeaderFields(fields) => {
                            Section::HeaderFields(Some(part_number), fields)
                        }
                        PartSpecifier::HeaderFieldsNot(fields) => {
                            Section::HeaderFieldsNot(Some(part_number), fields)
                        }
                        PartSpecifier::Text => Section::Text(Some(part_number)),
                        PartSpecifier::Mime => Section::Mime(part_number),
                    }
                } else {
                    Section::Part(part_number)
                }
            },
        ),
    ));

    let (remaining, parsed_section_spec) = parser(input)?;

    Ok((remaining, parsed_section_spec))
}

/// section-msgtext = "HEADER" / "HEADER.FIELDS" [".NOT"] SP header-list / "TEXT"
///                    ; top-level or MESSAGE/RFC822 part
pub fn section_msgtext(input: &[u8]) -> IResult<&[u8], PartSpecifier> {
    let parser = alt((
        map(
            tuple((tag_no_case(b"HEADER.FIELDS.NOT"), sp, header_list)),
            |(_, _, header_list)| PartSpecifier::HeaderFieldsNot(header_list),
        ),
        map(
            tuple((tag_no_case(b"HEADER.FIELDS"), sp, header_list)),
            |(_, _, header_list)| PartSpecifier::HeaderFields(header_list),
        ),
        value(PartSpecifier::Header, tag_no_case(b"HEADER")),
        value(PartSpecifier::Text, tag_no_case(b"TEXT")),
    ));

    let (remaining, parsed_section_msgtext) = parser(input)?;

    Ok((remaining, parsed_section_msgtext))
}

/// section-part = nz-number *("." nz-number)
///                  ; body part nesting
pub fn section_part(input: &[u8]) -> IResult<&[u8], Vec<u32>> {
    let parser = separated_nonempty_list(tag_no_case(b"."), nz_number);

    let (remaining, parsed_section_part) = parser(input)?;

    Ok((remaining, parsed_section_part))
}

/// section-text = section-msgtext / "MIME"
///                  ; text other than actual body part (headers, etc.)
pub fn section_text(input: &[u8]) -> IResult<&[u8], PartSpecifier> {
    let parser = alt((
        section_msgtext,
        value(PartSpecifier::Mime, tag_no_case(b"MIME")),
    ));

    let (remaining, parsed_section_text) = parser(input)?;

    Ok((remaining, parsed_section_text))
}