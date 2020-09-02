//! # 7. Server Responses

use crate::{
    codec::Codec,
    types::{
        body::BodyStructure,
        core::{Atom, Charset, NString},
        data_items::Section,
        envelope::Envelope,
        flag::{Flag, FlagNameAttribute},
        mailbox::Mailbox,
        Capability,
    },
    utils::{join, join_bytes, join_serializable},
};
use chrono::{DateTime, FixedOffset};
use serde::Deserialize;

/// Server responses are in three forms.
#[derive(Debug, Clone, PartialEq)]
pub enum Response {
    /// Status responses can be tagged or untagged.  Tagged status responses
    /// indicate the completion result (OK, NO, or BAD status) of a client
    /// command, and have a tag matching the command.
    Status(Status),
    /// All server data is untagged. An untagged response is indicated by the
    /// token "*" instead of a tag. Untagged status responses indicate server
    /// greeting, or server status that does not indicate the completion of a
    /// command (for example, an impending system shutdown alert).
    Data(Data),
    /// Command continuation request responses use the token "+" instead of a
    /// tag.  These responses are sent by the server to indicate acceptance
    /// of an incomplete client command and readiness for the remainder of
    /// the command.
    Continuation(Continuation),
}

impl Codec for Response {
    fn serialize(&self) -> Vec<u8> {
        match self {
            Response::Status(status) => status.serialize(),
            Response::Data(data) => data.serialize(),
            Response::Continuation(continuation) => continuation.serialize(),
        }
    }

    fn deserialize(_input: &[u8]) -> Result<(&[u8], Self), Self>
    where
        Self: Sized,
    {
        unimplemented!()
    }
}

// FIXME: IMAP tags != UTF-8 String
pub type Tag = String;

// FIXME: IMAP text != UTF-8 String, must not be empty
pub type Text = String;

/// ## 7.1. Server Responses - Status Responses
///
/// Status responses are OK, NO, BAD, PREAUTH and BYE.
/// OK, NO, and BAD can be tagged or untagged.
/// PREAUTH and BYE are always untagged.
/// Status responses MAY include an OPTIONAL "response code" (see [ResponseCode](ResponseCode).)
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub enum Status {
    /// ### 7.1.1. OK Response
    ///
    /// The OK response indicates an information message from the server.
    ///
    /// # Trace
    ///
    /// ```text
    /// S: * OK IMAP4rev1 server ready
    /// C: A001 LOGIN fred blurdybloop
    /// S: * OK [ALERT] System shutdown in 10 minutes
    /// S: A001 OK LOGIN Completed
    /// ```
    Ok {
        /// When tagged, it indicates successful completion of the associated
        /// command.  The human-readable text MAY be presented to the user as
        /// an information message.
        ///
        /// The untagged form indicates an information-only message; the nature
        /// of the information MAY be indicated by a response code.
        ///
        /// The untagged form is also used as one of three possible greetings
        /// at connection startup.  It indicates that the connection is not
        /// yet authenticated and that a LOGIN command is needed.
        tag: Option<Tag>,
        /// Response code (optional)
        code: Option<Code>,
        /// Human-readable text (must be at least 1 character!)
        text: Text,
    },

    /// ### 7.1.2. NO Response
    ///
    /// The NO response indicates an operational error message from the server.
    ///
    /// # Trace
    ///
    /// ```text
    /// C: A222 COPY 1:2 owatagusiam
    /// S: * NO Disk is 98% full, please delete unnecessary data
    /// S: A222 OK COPY completed
    /// C: A223 COPY 3:200 blurdybloop
    /// S: * NO Disk is 98% full, please delete unnecessary data
    /// S: * NO Disk is 99% full, please delete unnecessary data
    /// S: A223 NO COPY failed: disk is full
    /// ```
    No {
        /// When tagged, it indicates unsuccessful completion of the
        /// associated command.  The untagged form indicates a warning; the
        /// command can still complete successfully.
        tag: Option<Tag>,
        /// Response code (optional)
        code: Option<Code>,
        /// The human-readable text describes the condition. (must be at least 1 character!)
        text: Text,
    },

    /// ### 7.1.3. BAD Response
    ///
    /// The BAD response indicates an error message from the server.
    ///
    /// # Trace
    ///
    /// ```text
    /// C: ...very long command line...
    /// S: * BAD Command line too long
    /// C: ...empty line...
    /// S: * BAD Empty command line
    /// C: A443 EXPUNGE
    /// S: * BAD Disk crash, attempting salvage to a new disk!
    /// S: * OK Salvage successful, no data lost
    /// S: A443 OK Expunge completed
    /// ```
    Bad {
        /// When tagged, it reports a protocol-level error in the client's command;
        /// the tag indicates the command that caused the error.  The untagged
        /// form indicates a protocol-level error for which the associated
        /// command can not be determined; it can also indicate an internal
        /// server failure.
        tag: Option<Tag>,
        /// Response code (optional)
        code: Option<Code>,
        /// The human-readable text describes the condition. (must be at least 1 character!)
        text: Text,
    },

    /// ### 7.1.4. PREAUTH Response
    ///
    /// The PREAUTH response is always untagged, and is one of three
    /// possible greetings at connection startup.  It indicates that the
    /// connection has already been authenticated by external means; thus
    /// no LOGIN command is needed.
    ///
    /// # Trace
    ///
    /// ```text
    /// S: * PREAUTH IMAP4rev1 server logged in as Smith
    /// ```
    PreAuth {
        /// Response code (optional)
        code: Option<Code>,
        /// Human-readable text (must be at least 1 character!)
        text: Text,
    },

    /// ### 7.1.5. BYE Response
    ///
    /// The BYE response is always untagged, and indicates that the server
    /// is about to close the connection.
    ///
    /// The BYE response is sent under one of four conditions:
    ///
    ///    1) as part of a normal logout sequence.  The server will close
    ///       the connection after sending the tagged OK response to the
    ///       LOGOUT command.
    ///
    ///    2) as a panic shutdown announcement.  The server closes the
    ///       connection immediately.
    ///
    ///    3) as an announcement of an inactivity autologout.  The server
    ///       closes the connection immediately.
    ///
    ///    4) as one of three possible greetings at connection startup,
    ///       indicating that the server is not willing to accept a
    ///       connection from this client.  The server closes the
    ///       connection immediately.
    ///
    /// The difference between a BYE that occurs as part of a normal
    /// LOGOUT sequence (the first case) and a BYE that occurs because of
    /// a failure (the other three cases) is that the connection closes
    /// immediately in the failure case.  In all cases the client SHOULD
    /// continue to read response data from the server until the
    /// connection is closed; this will ensure that any pending untagged
    /// or completion responses are read and processed.
    ///
    /// # Trace
    ///
    /// ```text
    /// S: * BYE Autologout; idle for too long
    /// ```
    Bye {
        /// Response code (optional)
        code: Option<Code>,
        /// The human-readable text MAY be displayed to the user in a status
        /// report by the client. (must be at least 1 character!)
        text: Text,
    },
}

impl Status {
    pub fn greeting(code: Option<Code>, text: &str) -> Self {
        Status::Ok {
            tag: None,
            code,
            text: text.to_owned(),
        }
    }

    pub fn ok(tag: Option<&str>, code: Option<Code>, text: &str) -> Self {
        Status::Ok {
            tag: tag.map(str::to_owned),
            code,
            text: text.to_owned(),
        }
    }

    pub fn no(tag: Option<&str>, code: Option<Code>, text: &str) -> Self {
        Status::No {
            tag: tag.map(str::to_owned),
            code,
            text: text.to_owned(),
        }
    }

    pub fn bad(tag: Option<&str>, code: Option<Code>, text: &str) -> Self {
        Status::Bad {
            tag: tag.map(str::to_owned),
            code,
            text: text.to_owned(),
        }
    }

    pub fn preauth(code: Option<Code>, text: &str) -> Self {
        Status::PreAuth {
            code,
            text: text.to_owned(),
        }
    }

    pub fn bye(code: Option<Code>, text: &str) -> Self {
        Status::Bye {
            code,
            text: text.to_owned(),
        }
    }
}

impl Codec for Status {
    fn serialize(&self) -> Vec<u8> {
        fn format_status(
            tag: &Option<String>,
            status: &str,
            code: &Option<Code>,
            comment: &str,
        ) -> String {
            let tag = tag.as_deref().unwrap_or("*");

            match code {
                Some(code) => format!("{} {} [{}] {}\r\n", tag, status, code, comment),
                None => format!("{} {} {}\r\n", tag, status, comment),
            }
        }

        match self {
            Status::Ok { tag, code, text } => format_status(tag, "OK", code, text).into_bytes(),
            Status::No { tag, code, text } => format_status(tag, "NO", code, text).into_bytes(),
            Status::Bad { tag, code, text } => format_status(tag, "BAD", code, text).into_bytes(),
            Status::PreAuth { code, text } => {
                format_status(&None, "PREAUTH", code, text).into_bytes()
            }
            Status::Bye { code, text } => format_status(&None, "BYE", code, text).into_bytes(),
        }
    }

    fn deserialize(_input: &[u8]) -> Result<(&[u8], Self), Status>
    where
        Self: Sized,
    {
        unimplemented!()
    }
}

/// ## 7.2 - 7.4 Server and Mailbox Status; Mailbox Size; Message Status
#[derive(Debug, Clone, PartialEq)]
pub enum Data {
    // ## 7.2. Server Responses - Server and Mailbox Status
    //
    // These responses are always untagged.  This is how server and mailbox
    // status data are transmitted from the server to the client.  Many of
    // these responses typically result from a command with the same name.
    /// ### 7.2.1. CAPABILITY Response
    ///
    /// * Contents: capability listing
    ///
    /// The CAPABILITY response occurs as a result of a CAPABILITY
    /// command.  The capability listing contains a space-separated
    /// listing of capability names that the server supports.  The
    /// capability listing MUST include the atom "IMAP4rev1".
    ///
    /// In addition, client and server implementations MUST implement the
    /// STARTTLS, LOGINDISABLED, and AUTH=PLAIN (described in [IMAP-TLS])
    /// capabilities.  See the Security Considerations section for
    /// important information.
    ///
    /// A capability name which begins with "AUTH=" indicates that the
    /// server supports that particular authentication mechanism.
    ///
    /// The LOGINDISABLED capability indicates that the LOGIN command is
    /// disabled, and that the server will respond with a tagged NO
    /// response to any attempt to use the LOGIN command even if the user
    /// name and password are valid.  An IMAP client MUST NOT issue the
    /// LOGIN command if the server advertises the LOGINDISABLED
    /// capability.
    ///
    /// Other capability names indicate that the server supports an
    /// extension, revision, or amendment to the IMAP4rev1 protocol.
    /// Server responses MUST conform to this document until the client
    /// issues a command that uses the associated capability.
    ///
    /// Capability names MUST either begin with "X" or be standard or
    /// standards-track IMAP4rev1 extensions, revisions, or amendments
    /// registered with IANA.  A server MUST NOT offer unregistered or
    /// non-standard capability names, unless such names are prefixed with
    /// an "X".
    ///
    /// Client implementations SHOULD NOT require any capability name
    /// other than "IMAP4rev1", and MUST ignore any unknown capability
    /// names.
    ///
    /// A server MAY send capabilities automatically, by using the
    /// CAPABILITY response code in the initial PREAUTH or OK responses,
    /// and by sending an updated CAPABILITY response code in the tagged
    /// OK response as part of a successful authentication.  It is
    /// unnecessary for a client to send a separate CAPABILITY command if
    /// it recognizes these automatic capabilities.
    ///
    /// # Trace
    ///
    /// ```text
    /// S: * CAPABILITY IMAP4rev1 STARTTLS AUTH=GSSAPI XPIG-LATIN
    /// ```
    Capability(Vec<Capability>),

    /// ### 7.2.2. LIST Response
    ///
    /// The LIST response occurs as a result of a LIST command.  It
    /// returns a single name that matches the LIST specification.  There
    /// can be multiple LIST responses for a single LIST command.
    ///
    /// The hierarchy delimiter is a character used to delimit levels of
    /// hierarchy in a mailbox name.  A client can use it to create child
    /// mailboxes, and to search higher or lower levels of naming
    /// hierarchy.  All children of a top-level hierarchy node MUST use
    /// the same separator character.  A NIL hierarchy delimiter means
    /// that no hierarchy exists; the name is a "flat" name.
    ///
    /// The name represents an unambiguous left-to-right hierarchy, and
    /// MUST be valid for use as a reference in LIST and LSUB commands.
    /// Unless \Noselect is indicated, the name MUST also be valid as an
    /// argument for commands, such as SELECT, that accept mailbox names.
    ///
    /// # Trace
    ///
    /// ```text
    /// S: * LIST (\Noselect) "/" ~/Mail/foo
    /// ```
    List {
        /// Name attributes
        items: Vec<FlagNameAttribute>,
        /// Hierarchy delimiter
        delimiter: Option<char>,
        /// Name
        mailbox: Mailbox,
    },

    /// ### 7.2.3. LSUB Response
    ///
    /// The LSUB response occurs as a result of an LSUB command.  It
    /// returns a single name that matches the LSUB specification.  There
    /// can be multiple LSUB responses for a single LSUB command.  The
    /// data is identical in format to the LIST response.
    ///
    /// # Trace
    ///
    /// ```text
    /// S: * LSUB () "." #news.comp.mail.misc
    /// ```
    Lsub {
        /// Name attributes
        items: Vec<FlagNameAttribute>,
        /// Hierarchy delimiter
        delimiter: String,
        /// Name
        name: String, // TODO: `String` or `Mailbox`?
    },

    /// ### 7.2.4 STATUS Response
    ///
    /// The STATUS response occurs as a result of an STATUS command.  It
    /// returns the mailbox name that matches the STATUS specification and
    /// the requested mailbox status information.
    ///
    /// # Trace
    ///
    /// ```text
    /// S: * STATUS blurdybloop (MESSAGES 231 UIDNEXT 44292)
    /// ```
    Status {
        /// Name
        name: Mailbox,
        /// Status parenthesized list
        items: Vec<StatusItemResponse>,
    },

    /// ### 7.2.5. SEARCH Response
    ///
    /// * Contents: zero or more numbers
    ///
    /// The SEARCH response occurs as a result of a SEARCH or UID SEARCH
    /// command.  The number(s) refer to those messages that match the
    /// search criteria.  For SEARCH, these are message sequence numbers;
    /// for UID SEARCH, these are unique identifiers.  Each number is
    /// delimited by a space.
    ///
    /// # Trace
    ///
    /// ```text
    /// S: * SEARCH 2 3 6
    /// ```
    Search(Vec<u32>),

    /// ### 7.2.6.  FLAGS Response
    ///
    /// * Contents: flag parenthesized list
    ///
    /// The FLAGS response occurs as a result of a SELECT or EXAMINE
    /// command.  The flag parenthesized list identifies the flags (at a
    /// minimum, the system-defined flags) that are applicable for this
    /// mailbox.  Flags other than the system flags can also exist,
    /// depending on server implementation.
    ///
    /// The update from the FLAGS response MUST be recorded by the client.
    ///
    /// # Trace
    ///
    /// ```text
    /// S: * FLAGS (\Answered \Flagged \Deleted \Seen \Draft)
    /// ```
    Flags(Vec<Flag>),

    // ## 7.3. Server Responses - Mailbox Size
    //
    // These responses are always untagged.  This is how changes in the size
    // of the mailbox are transmitted from the server to the client.
    // Immediately following the "*" token is a number that represents a
    // message count.
    /// ### 7.3.1. EXISTS Response
    ///
    /// The EXISTS response reports the number of messages in the mailbox.
    /// This response occurs as a result of a SELECT or EXAMINE command,
    /// and if the size of the mailbox changes (e.g., new messages).
    ///
    /// The update from the EXISTS response MUST be recorded by the client.
    ///
    /// # Trace
    ///
    /// ```text
    /// S: * 23 EXISTS
    /// ```
    Exists(u32),

    /// ### 7.3.2. RECENT Response
    ///
    /// The RECENT response reports the number of messages with the
    /// \Recent flag set.  This response occurs as a result of a SELECT or
    /// EXAMINE command, and if the size of the mailbox changes (e.g., new
    /// messages).
    ///
    ///   Note: It is not guaranteed that the message sequence
    ///   numbers of recent messages will be a contiguous range of
    ///   the highest n messages in the mailbox (where n is the
    ///   value reported by the RECENT response).  Examples of
    ///   situations in which this is not the case are: multiple
    ///   clients having the same mailbox open (the first session
    ///   to be notified will see it as recent, others will
    ///   probably see it as non-recent), and when the mailbox is
    ///   re-ordered by a non-IMAP agent.
    ///
    ///   The only reliable way to identify recent messages is to
    ///   look at message flags to see which have the \Recent flag
    ///   set, or to do a SEARCH RECENT.
    ///
    /// The update from the RECENT response MUST be recorded by the client.
    ///
    /// # Trace
    ///
    /// ```text
    /// S: * 5 RECENT
    /// ```
    Recent(u32),

    // ## 7.4. Server Responses - Message Status
    //
    // These responses are always untagged.  This is how message data are
    // transmitted from the server to the client, often as a result of a
    // command with the same name.  Immediately following the "*" token is a
    // number that represents a message sequence number.
    /// ### 7.4.1. EXPUNGE Response
    ///
    /// The EXPUNGE response reports that the specified message sequence
    /// number has been permanently removed from the mailbox.  The message
    /// sequence number for each successive message in the mailbox is
    /// immediately decremented by 1, and this decrement is reflected in
    /// message sequence numbers in subsequent responses (including other
    /// untagged EXPUNGE responses).
    ///
    /// The EXPUNGE response also decrements the number of messages in the
    /// mailbox; it is not necessary to send an EXISTS response with the
    /// new value.
    ///
    /// As a result of the immediate decrement rule, message sequence
    /// numbers that appear in a set of successive EXPUNGE responses
    /// depend upon whether the messages are removed starting from lower
    /// numbers to higher numbers, or from higher numbers to lower
    /// numbers.  For example, if the last 5 messages in a 9-message
    /// mailbox are expunged, a "lower to higher" server will send five
    /// untagged EXPUNGE responses for message sequence number 5, whereas
    /// a "higher to lower server" will send successive untagged EXPUNGE
    /// responses for message sequence numbers 9, 8, 7, 6, and 5.
    ///
    /// An EXPUNGE response MUST NOT be sent when no command is in
    /// progress, nor while responding to a FETCH, STORE, or SEARCH
    /// command.  This rule is necessary to prevent a loss of
    /// synchronization of message sequence numbers between client and
    /// server.  A command is not "in progress" until the complete command
    /// has been received; in particular, a command is not "in progress"
    /// during the negotiation of command continuation.
    ///
    ///   Note: UID FETCH, UID STORE, and UID SEARCH are different
    ///   commands from FETCH, STORE, and SEARCH.  An EXPUNGE
    ///   response MAY be sent during a UID command.
    ///
    /// The update from the EXPUNGE response MUST be recorded by the client.
    ///
    /// # Trace
    ///
    /// ```text
    /// S: * 44 EXPUNGE
    /// ```
    Expunge(u32),

    /// ### 7.4.2. FETCH Response
    ///
    /// The FETCH response returns data about a message to the client.
    /// The data are pairs of data item names and their values in
    /// parentheses.  This response occurs as the result of a FETCH or
    /// STORE command, as well as by unilateral server decision (e.g.,
    /// flag updates).
    ///
    /// # Trace
    ///
    /// ```text
    /// S: * 23 FETCH (FLAGS (\Seen) RFC822.SIZE 44827)
    /// ```
    Fetch {
        /// Message SEQ or UID
        msg: u32,
        /// Message data
        items: Vec<DataItemResponse>,
    },
}

impl Codec for Data {
    fn serialize(&self) -> Vec<u8> {
        match self {
            Data::Capability(caps) => format!("* CAPABILITY {}\r\n", join(caps, " ")).into_bytes(),
            Data::List {
                items,
                delimiter,
                mailbox,
            } => {
                let mut out = b"* LIST (".to_vec();
                out.extend(join_serializable(items, b" "));
                out.extend_from_slice(b") ");
                if let Some(delimiter) = delimiter {
                    out.extend(format!("\"{}\"", delimiter).as_bytes());
                } else {
                    out.extend_from_slice(b"nil");
                }
                out.push(b' ');
                out.extend(mailbox.serialize());
                out.extend_from_slice(b"\r\n");
                out
            }
            Data::Lsub {
                items,
                delimiter,
                name,
            } => format!(
                "* LSUB ({}) \"{}\" {}\r\n",
                join(items, " "),
                delimiter,
                name
            )
            .into_bytes(),
            Data::Status { name, items } => [
                b"* STATUS ".as_ref(),
                name.serialize().as_ref(),
                b" (",
                join(items, " ").as_bytes(),
                b")\r\n",
            ]
            .concat(),
            Data::Search(seqs) => {
                if seqs.is_empty() {
                    "* SEARCH\r\n".to_string().into_bytes()
                } else {
                    format!("* SEARCH {}\r\n", join(seqs, " ")).into_bytes()
                }
            }
            Data::Flags(flags) => format!("* FLAGS ({})\r\n", join(flags, " ")).into_bytes(),
            Data::Exists(count) => format!("* {} EXISTS\r\n", count).into_bytes(),
            Data::Recent(count) => format!("* {} RECENT\r\n", count).into_bytes(),
            Data::Expunge(msg) => format!("* {} EXPUNGE\r\n", msg).into_bytes(),
            Data::Fetch { msg, items } => [
                b"* ".as_ref(),
                msg.to_string().as_bytes(),
                b" FETCH (",
                join_bytes(items.iter().map(|item| item.serialize()).collect(), b" ").as_ref(),
                b")\r\n",
            ]
            .concat(),
        }
    }

    fn deserialize(_input: &[u8]) -> Result<(&[u8], Self), Data>
    where
        Self: Sized,
    {
        unimplemented!()
    }
}

pub type Inbox = String;

/// The currently defined status data items.
#[derive(Debug, Clone, PartialEq)]
pub enum StatusItemResponse {
    /// The number of messages in the mailbox.
    Messages(u32),

    /// The number of messages with the \Recent flag set.
    Recent(u32),

    /// The next unique identifier value of the mailbox.  Refer to
    /// section 2.3.1.1 for more information.
    UidNext(u32),

    /// The unique identifier validity value of the mailbox.  Refer to
    /// section 2.3.1.1 for more information.
    UidValidity(u32),

    /// The number of messages which do not have the \Seen flag set.
    Unseen(u32),
}

impl std::fmt::Display for StatusItemResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Self::Messages(count) => write!(f, "MESSAGES {}", count),
            Self::Recent(count) => write!(f, "RECENT {}", count),
            Self::UidNext(next) => write!(f, "UIDNEXT {}", next),
            Self::UidValidity(identifier) => write!(f, "UIDVALIDITY {}", identifier),
            Self::Unseen(count) => write!(f, "UNSEEN {}", count),
        }
    }
}

/// ## 7.5. Server Responses - Command Continuation Request
///
/// The command continuation request response is indicated by a "+" token
/// instead of a tag.  This form of response indicates that the server is
/// ready to accept the continuation of a command from the client.  The
/// remainder of this response is a line of text.
///
/// This response is used in the AUTHENTICATE command to transmit server
/// data to the client, and request additional client data.  This
/// response is also used if an argument to any command is a literal.
///
/// The client is not permitted to send the octets of the literal unless
/// the server indicates that it is expected.  This permits the server to
/// process commands and reject errors on a line-by-line basis.  The
/// remainder of the command, including the CRLF that terminates a
/// command, follows the octets of the literal.  If there are any
/// additional command arguments, the literal octets are followed by a
/// space and those arguments.
///
/// # Trace
///
/// ```text
/// C: A001 LOGIN {11}
/// S: + Ready for additional command text
/// C: FRED FOOBAR {7}
/// S: + Ready for additional command text
/// C: fat man
/// S: A001 OK LOGIN completed
/// C: A044 BLURDYBLOOP {102856}
/// S: A044 BAD No such command as "BLURDYBLOOP"
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Continuation {
    Basic { code: Option<Code>, text: String },
    Base64(String),
}

impl Continuation {
    pub fn basic(code: Option<Code>, text: &str) -> Self {
        // TODO: empty text is not allowed in continuation
        let text = if text.is_empty() {
            ".".to_owned()
        } else {
            text.to_owned()
        };

        Continuation::Basic { code, text }
    }

    pub fn base64(data: &str) -> Self {
        Continuation::Base64(data.to_owned())
    }
}

impl Codec for Continuation {
    fn serialize(&self) -> Vec<u8> {
        match self {
            Continuation::Basic { code, text } => match code {
                Some(ref code) => format!("+ [{}] {}\r\n", code, text).into_bytes(),
                None => format!("+ {}\r\n", text).into_bytes(),
            },
            Continuation::Base64(data) => format!("+ {}\r\n", data).into_bytes(),
        }
    }

    fn deserialize(_input: &[u8]) -> Result<(&[u8], Self), Continuation>
    where
        Self: Sized,
    {
        unimplemented!()
    }
}

/// A response code consists of data inside square brackets in the form of an atom,
/// possibly followed by a space and arguments.  The response code
/// contains additional information or status codes for client software
/// beyond the OK/NO/BAD condition, and are defined when there is a
/// specific action that a client can take based upon the additional
/// information.
///
/// The currently defined response codes are:
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum Code {
    /// `ALERT`
    ///
    /// The human-readable text contains a special alert that MUST be
    /// presented to the user in a fashion that calls the user's
    /// attention to the message.
    Alert,

    /// `BADCHARSET`
    ///
    /// Optionally followed by a parenthesized list of charsets.  A
    /// SEARCH failed because the given charset is not supported by
    /// this implementation.  If the optional list of charsets is
    /// given, this lists the charsets that are supported by this
    /// implementation.
    BadCharset(Vec<Charset>),

    /// `CAPABILITY`
    ///
    /// Followed by a list of capabilities.  This can appear in the
    /// initial OK or PREAUTH response to transmit an initial
    /// capabilities list.  This makes it unnecessary for a client to
    /// send a separate CAPABILITY command if it recognizes this
    /// response.
    Capability(Vec<Capability>),

    /// `PARSE`
    ///
    /// The human-readable text represents an error in parsing the
    /// [RFC-2822] header or [MIME-IMB] headers of a message in the
    /// mailbox.
    Parse,

    /// `PERMANENTFLAGS`
    ///
    /// Followed by a parenthesized list of flags, indicates which of
    /// the known flags the client can change permanently.  Any flags
    /// that are in the FLAGS untagged response, but not the
    /// PERMANENTFLAGS list, can not be set permanently.  If the client
    /// attempts to STORE a flag that is not in the PERMANENTFLAGS
    /// list, the server will either ignore the change or store the
    /// state change for the remainder of the current session only.
    /// The PERMANENTFLAGS list can also include the special flag \*,
    /// which indicates that it is possible to create new keywords by
    /// attempting to store those flags in the mailbox.
    PermanentFlags(Vec<Flag>),

    /// `READ-ONLY`
    ///
    /// The mailbox is selected read-only, or its access while selected
    /// has changed from read-write to read-only.
    ReadOnly,

    /// `READ-WRITE`
    ///
    /// The mailbox is selected read-write, or its access while
    /// selected has changed from read-only to read-write.
    ReadWrite,

    /// `TRYCREATE`
    ///
    /// An APPEND or COPY attempt is failing because the target mailbox
    /// does not exist (as opposed to some other reason).  This is a
    /// hint to the client that the operation can succeed if the
    /// mailbox is first created by the CREATE command.
    TryCreate,

    /// `UIDNEXT`
    ///
    /// Followed by a decimal number, indicates the next unique
    /// identifier value.  Refer to section 2.3.1.1 for more
    /// information.
    UidNext(u32),

    /// `UIDVALIDITY`
    ///
    /// Followed by a decimal number, indicates the unique identifier
    /// validity value.  Refer to section 2.3.1.1 for more information.
    UidValidity(u32),

    /// `UNSEEN`
    ///
    /// Followed by a decimal number, indicates the number of the first
    /// message without the \Seen flag set.
    Unseen(u32),

    /// Additional response codes defined by particular client or server
    /// implementations SHOULD be prefixed with an "X" until they are
    /// added to a revision of this protocol.  Client implementations
    /// SHOULD ignore response codes that they do not recognize.
    Other(Atom, Option<String>),

    /// IMAP4 Login Referrals (RFC 2221)
    Referral(String), // TODO: the imap url is more complicated than that...
}

impl Code {
    pub fn capability(caps: &[Capability]) -> Self {
        Code::Capability(caps.to_vec())
    }
}

impl std::fmt::Display for Code {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Code::Alert => write!(f, "ALERT"),
            Code::BadCharset(charsets) => {
                if charsets.is_empty() {
                    write!(f, "BADCHARSET")
                } else {
                    write!(f, "BADCHARSET ({})", &join(charsets, " "))
                }
            }
            Code::Capability(caps) => write!(f, "CAPABILITY {}", join(caps, " ")),
            Code::Parse => write!(f, "PARSE"),
            Code::PermanentFlags(flags) => write!(f, "PERMANENTFLAGS ({})", join(flags, " ")),
            Code::ReadOnly => write!(f, "READ-ONLY"),
            Code::ReadWrite => write!(f, "READ-WRITE"),
            Code::TryCreate => write!(f, "TRYCREATE"),
            Code::UidNext(next) => write!(f, "UIDNEXT {}", next),
            Code::UidValidity(validity) => write!(f, "UIDVALIDITY {}", validity),
            Code::Unseen(seq) => write!(f, "UNSEEN {}", seq),
            Code::Other(atom, params) => match params {
                Some(params) => write!(f, "{} {}", atom, params),
                None => write!(f, "{}", atom),
            },
            // RFC 2221
            Code::Referral(url) => write!(f, "REFERRAL {}", url),
        }
    }
}

impl Codec for Code {
    fn serialize(&self) -> Vec<u8> {
        self.to_string().into_bytes()
    }

    fn deserialize(_input: &[u8]) -> Result<(&[u8], Self), Self>
    where
        Self: Sized,
    {
        unimplemented!()
    }
}

/// The current data items are:
#[derive(Debug, Clone, PartialEq)]
pub enum DataItemResponse {
    /// `BODY`
    ///
    /// A form of BODYSTRUCTURE without extension data.
    Body(BodyStructure),

    /// `BODY[<section>]<<origin octet>>`
    ///
    /// A string expressing the body contents of the specified section.
    /// The string SHOULD be interpreted by the client according to the
    /// content transfer encoding, body type, and subtype.
    ///
    /// If the origin octet is specified, this string is a substring of
    /// the entire body contents, starting at that origin octet.  This
    /// means that BODY[]<0> MAY be truncated, but BODY[] is NEVER
    /// truncated.
    ///
    ///    Note: The origin octet facility MUST NOT be used by a server
    ///    in a FETCH response unless the client specifically requested
    ///    it by means of a FETCH of a BODY[<section>]<<partial>> data
    ///    item.
    ///
    /// 8-bit textual data is permitted if a [CHARSET] identifier is
    /// part of the body parameter parenthesized list for this section.
    /// Note that headers (part specifiers HEADER or MIME, or the
    /// header portion of a MESSAGE/RFC822 part), MUST be 7-bit; 8-bit
    /// characters are not permitted in headers.  Note also that the
    /// [RFC-2822] delimiting blank line between the header and the
    /// body is not affected by header line subsetting; the blank line
    /// is always included as part of header data, except in the case
    /// of a message which has no body and no blank line.
    ///
    /// Non-textual data such as binary data MUST be transfer encoded
    /// into a textual form, such as BASE64, prior to being sent to the
    /// client.  To derive the original binary data, the client MUST
    /// decode the transfer encoded string.
    BodyExt {
        section: Option<Section>,
        origin: Option<u32>,
        data: NString,
    },

    /// `BODYSTRUCTURE`
    ///
    /// A parenthesized list that describes the [MIME-IMB] body
    /// structure of a message.  This is computed by the server by
    /// parsing the [MIME-IMB] header fields, defaulting various fields
    /// as necessary.
    ///
    /// See [BodyStructure](struct.BodyStructure.html).
    BodyStructure(BodyStructure),

    /// `ENVELOPE`
    ///
    /// A parenthesized list that describes the envelope structure of a
    /// message.  This is computed by the server by parsing the
    /// [RFC-2822] header into the component parts, defaulting various
    /// fields as necessary.
    ///
    /// See [Envelope](struct.Envelope.html).
    Envelope(Envelope),

    /// `FLAGS`
    ///
    /// A parenthesized list of flags that are set for this message.
    Flags(Vec<Flag>),

    /// `INTERNALDATE`
    ///
    /// A string representing the internal date of the message.
    InternalDate(DateTime<FixedOffset>),

    /// `RFC822`
    ///
    /// Equivalent to BODY[].
    Rfc822(NString),

    /// `RFC822.HEADER`
    ///
    /// Equivalent to BODY[HEADER].  Note that this did not result in
    /// \Seen being set, because RFC822.HEADER response data occurs as
    /// a result of a FETCH of RFC822.HEADER.  BODY[HEADER] response
    /// data occurs as a result of a FETCH of BODY[HEADER] (which sets
    /// \Seen) or BODY.PEEK[HEADER] (which does not set \Seen).
    Rfc822Header(NString),

    /// `RFC822.SIZE`
    ///
    /// A number expressing the [RFC-2822] size of the message.
    Rfc822Size(u32),

    /// `RFC822.TEXT`
    ///
    /// Equivalent to BODY[TEXT].
    Rfc822Text(NString),

    /// `UID`
    ///
    /// A number expressing the unique identifier of the message.
    Uid(u32),
}

impl Codec for DataItemResponse {
    fn serialize(&self) -> Vec<u8> {
        match self {
            DataItemResponse::Body(_structure) => unimplemented!(),
            DataItemResponse::BodyExt {
                section: _,
                origin: _,
                data: _,
            } => unimplemented!(),
            DataItemResponse::BodyStructure(_structure) => unimplemented!(),
            DataItemResponse::Envelope(_envelope) => unimplemented!(),
            DataItemResponse::Flags(flags) => format!("({})", join(flags, " ")).into_bytes(),
            DataItemResponse::InternalDate(_datetime) => unimplemented!(),
            DataItemResponse::Rfc822(nstring) => {
                [b"RFC822 ".as_ref(), nstring.serialize().as_ref()].concat()
            }
            DataItemResponse::Rfc822Header(nstring) => {
                [b"RFC822.HEADER ".as_ref(), nstring.serialize().as_ref()].concat()
            }
            DataItemResponse::Rfc822Size(size) => format!("RFC822.SIZE {}", size).into_bytes(),
            DataItemResponse::Rfc822Text(nstring) => {
                [b"RFC822.TEXT ".as_ref(), nstring.serialize().as_ref()].concat()
            }
            DataItemResponse::Uid(uid) => format!("UID {}", uid).into_bytes(),
        }
    }

    fn deserialize(_input: &[u8]) -> Result<(&[u8], Self), DataItemResponse>
    where
        Self: Sized,
    {
        unimplemented!()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    // use std::convert::TryFrom;

    #[test]
    fn test_status() {
        let tests: Vec<(_, &[u8])> = vec![
            // tagged; Ok, No, Bad
            (
                Status::ok(Some("A1"), Some(Code::Alert), "hello"),
                b"A1 OK [ALERT] hello\r\n",
            ),
            (
                Status::no(Some("A1"), Some(Code::Alert), "hello"),
                b"A1 NO [ALERT] hello\r\n",
            ),
            (
                Status::bad(Some("A1"), Some(Code::Alert), "hello"),
                b"A1 BAD [ALERT] hello\r\n",
            ),
            (Status::ok(Some("A1"), None, "hello"), b"A1 OK hello\r\n"),
            (Status::no(Some("A1"), None, "hello"), b"A1 NO hello\r\n"),
            (Status::bad(Some("A1"), None, "hello"), b"A1 BAD hello\r\n"),
            // untagged; Ok, No, Bad
            (
                Status::ok(None, Some(Code::Alert), "hello"),
                b"* OK [ALERT] hello\r\n",
            ),
            (
                Status::no(None, Some(Code::Alert), "hello"),
                b"* NO [ALERT] hello\r\n",
            ),
            (
                Status::bad(None, Some(Code::Alert), "hello"),
                b"* BAD [ALERT] hello\r\n",
            ),
            (Status::ok(None, None, "hello"), b"* OK hello\r\n"),
            (Status::no(None, None, "hello"), b"* NO hello\r\n"),
            (Status::bad(None, None, "hello"), b"* BAD hello\r\n"),
            // preauth
            (
                Status::preauth(Some(Code::Alert), "hello"),
                b"* PREAUTH [ALERT] hello\r\n",
            ),
            // bye
            (
                Status::bye(Some(Code::Alert), "hello"),
                b"* BYE [ALERT] hello\r\n",
            ),
        ];

        for (parsed, serialized) in tests {
            assert_eq!(parsed.serialize(), serialized.to_vec());
            // FIXME
            //assert_eq!(
            //    <Status as Codec>::deserialize(serialized).unwrap().1,
            //    parsed
            //);
        }
    }

    #[test]
    fn test_data() {
        let tests: Vec<(_, &[u8])> = vec![
            (
                Data::Capability(vec![Capability::Imap4Rev1]),
                b"* CAPABILITY IMAP4REV1\r\n",
            ),
            (
                Data::List {
                    items: vec![FlagNameAttribute::Noselect],
                    delimiter: Some('/'),
                    mailbox: "bbb".into(),
                },
                b"* LIST (\\Noselect) \"/\" bbb\r\n",
            ),
            (Data::Search(vec![1, 2, 3, 42]), b"* SEARCH 1 2 3 42\r\n"),
            (Data::Exists(42), b"* 42 EXISTS\r\n"),
            (Data::Recent(12345), b"* 12345 RECENT\r\n"),
            (Data::Expunge(123), b"* 123 EXPUNGE\r\n"),
        ];

        for (parsed, serialized) in tests.into_iter() {
            eprintln!("{:?}", parsed);
            assert_eq!(parsed.serialize(), serialized.to_vec());
            // FIXME:
            //assert_eq!(parsed, Data::deserialize(serialized).unwrap().1);
        }
    }

    #[test]
    fn test_continuation() {
        let tests: Vec<(_, &[u8])> = vec![
            (Continuation::basic(None, "hello"), b"+ hello\r\n".as_ref()),
            (Continuation::basic(None, ""), b"+ .\r\n"),
            (
                Continuation::basic(Some(Code::ReadWrite), "hello"),
                b"+ [READ-WRITE] hello\r\n",
            ),
            (
                Continuation::basic(Some(Code::ReadWrite), ""),
                b"+ [READ-WRITE] .\r\n",
            ),
        ];

        for (parsed, serialized) in tests.into_iter() {
            assert_eq!(parsed.serialize(), serialized.to_vec());
            // FIXME:
            //assert_eq!(parsed, Continuation::deserialize(serialized).unwrap().1);
        }
    }

    #[test]
    fn test_bodystructure() {
        /*
        let tests: Vec<(_, &[u8])> = vec![
            (
                BodyStructure::Single(Body {
                    parameter_list: vec![],
                    id: NString::String(IString::try_from("ares").unwrap()),
                    description: NString::Nil,
                    content_transfer_encoding: IString::try_from("xxx").unwrap(),
                    size: 123,
                    specific: SpecificFields::Basic {
                        type_: IString::try_from("application").unwrap(),
                        subtype: IString::try_from("voodoo").unwrap(),
                    },
                    extension: None,
                }),
                b"(\"application\" \"voodoo\" nil \"ares\" nil \"xxx\" 123)",
            ),
            (
                BodyStructure::Single(Body {
                    parameter_list: vec![],
                    id: NString::Nil,
                    description: NString::Nil,
                    content_transfer_encoding: IString::try_from("xxx").unwrap(),
                    size: 123,
                    specific: SpecificFields::Text {
                        subtype: IString::try_from("plain").unwrap(),
                        number_of_lines: 14,
                    },
                    extension: None,
                }),
                b"(\"text\" \"plain\" nil nil nil \"xxx\" 123 14)",
            ),
            (
                BodyStructure::Single(Body {
                    parameter_list: vec![],
                    id: NString::Nil,
                    description: NString::Nil,
                    content_transfer_encoding: IString::try_from("xxx").unwrap(),
                    size: 123,
                    specific: SpecificFields::MessageRfc822 {
                        envelope: Envelope {
                            date: IString::try_from("date").unwrap(),
                            subject: IString::try_from("subject").unwrap(),
                            from: vec![],
                            sender: vec![],
                            reply_to: vec![],
                            to: vec![],
                            cc: vec![],
                            bcc: vec![],
                            in_reply_to: IString::try_from("in-reply-to".to_string()).unwrap(),
                            message_id: IString::try_from("message-id".to_string()).unwrap(),
                        },
                        body_structure: Box::new(BodyStructure::Single(Body {
                            parameter_list: vec![],
                            id: NString::Nil,
                            description: NString::Nil,
                            content_transfer_encoding: IString::try_from("xxx").unwrap(),
                            size: 123,
                            specific: SpecificFields::Basic {
                                type_: IString::try_from("application").unwrap(),
                                subtype: IString::try_from("voodoo").unwrap(),
                            },
                            extension: None,
                        })),
                        number_of_lines: 14,
                    },
                    extension: None,
                }),
                b"(\"message\" \"rfc822\" nil nil nil \"xxx\" 123 ????????? (\"application\" \"voodoo\" nil nil nil \"xxx\" 123) 14)",
            ),
        ];

        for (parsed, serialized) in tests.into_iter() {
            assert_eq!(
                String::from_utf8(parsed.serialize()).unwrap(),
                String::from_utf8(serialized.to_vec()).unwrap()
            );
            //assert_eq!(parsed, BodyStructure::deserialize(serialized).unwrap().1);
        }
        */
    }
}
