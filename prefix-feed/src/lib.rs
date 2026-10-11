//! The public tag index: six bytes per tree position, in position order.
//!
//! Every Howl note is filed on chain under a discovery tag its owner can derive from a view
//! key alone. The server publishes the low-order six bytes of each leaf's tag, row `i` for
//! leaf `i`. A wallet keeps the rows, compares them with the tags it derives, and learns the
//! positions of its notes locally; it then asks for exactly those rows of the discovery
//! table. The index is the same bytes for every wallet and holds only values already on
//! chain.
//!
//! The low-order bytes are used because a tag is a BN254 scalar: its leading byte never
//! exceeds `0x30`, so the leading six bytes take about `2^45.6` values where the trailing six
//! take `2^48`.
//!
//! [`segment`] is the server half: rows from a cursor to the next segment boundary. A
//! segment that reaches its boundary never changes again, and it carries nothing that does:
//! where the list ends is read off the one segment that stops short of its boundary.
//! [`PrefixIndex`] is the wallet half: it absorbs segments, checks every re-read row against
//! the one it holds, and reports matching positions.
//!
//! A match is a candidate. Two tags share a prefix with probability `2^-48`, so the row a
//! wallet fetches for a match is still checked against the note commitment it recomputes.

#![deny(missing_docs)]

use std::collections::HashMap;

/// Bytes published per leaf.
pub const PREFIX_BYTES: usize = 6;

/// Rows in a full segment: 384 KiB on the wire.
pub const SEGMENT_ROWS: u64 = 65_536;

/// Rows a resumed walk re-reads at most, so the rows it holds are checked against the
/// server's before new ones are appended.
pub const RESUME_ALIGN_ROWS: u64 = 2_048;

/// The row of leaf 0, the genesis leaf, which has no tag.
pub const GENESIS_PREFIX: [u8; PREFIX_BYTES] = [0u8; PREFIX_BYTES];

const TAG_BYTES: usize = 32;

/// Why a segment could not be cut or absorbed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FeedError {
    /// The rows are not a whole number of prefixes.
    #[error("{len} bytes is not a whole number of {PREFIX_BYTES}-byte rows")]
    Ragged {
        /// Length supplied.
        len: usize,
    },
    /// The cursor is beyond the last row. The caller holds rows this index does not, so it
    /// is following another list or one that was rebuilt shorter.
    #[error("cursor {since} is past the {total} rows held")]
    PastFrontier {
        /// Cursor supplied.
        since: u64,
        /// Rows the index holds.
        total: u64,
    },
    /// A segment whose cursors disagree with the rows it carries, or that runs past its
    /// segment boundary.
    #[error("segment claims rows {base}..{next} and carries {rows}")]
    Inconsistent {
        /// First row claimed.
        base: u64,
        /// Row after the last one claimed.
        next: u64,
        /// Rows carried.
        rows: u64,
    },
    /// A segment that starts beyond the rows already held.
    #[error("segment starts at row {base} and only {held} rows are held")]
    Gap {
        /// First row of the segment.
        base: u64,
        /// Rows held.
        held: u64,
    },
    /// A re-read row differs from the one held: the list being followed changed.
    #[error("row {position} differs from the row held")]
    Diverged {
        /// First differing row.
        position: u64,
    },
}

/// The published prefix of a discovery tag: its low-order six bytes.
///
/// # Examples
/// ```
/// use howl_prefix_feed::tag_prefix;
/// let mut tag = [0u8; 32];
/// tag[0] = 0x30;
/// tag[31] = 7;
/// assert_eq!(tag_prefix(&tag), [0, 0, 0, 0, 0, 7]);
/// ```
#[must_use]
pub fn tag_prefix(tag: &[u8; TAG_BYTES]) -> [u8; PREFIX_BYTES] {
    let mut out = [0u8; PREFIX_BYTES];
    if let Some(low) = tag.get(TAG_BYTES - PREFIX_BYTES..) {
        out.copy_from_slice(low);
    }
    out
}

fn row_count(rows: &[u8]) -> Result<u64, FeedError> {
    if rows.len().is_multiple_of(PREFIX_BYTES) {
        Ok((rows.len() / PREFIX_BYTES) as u64)
    } else {
        Err(FeedError::Ragged { len: rows.len() })
    }
}

fn byte_offset(row: u64) -> usize {
    usize::try_from(row)
        .unwrap_or(usize::MAX)
        .saturating_mul(PREFIX_BYTES)
}

/// The segment boundary after `row`.
const fn boundary_after(row: u64) -> u64 {
    (row / SEGMENT_ROWS + 1).saturating_mul(SEGMENT_ROWS)
}

/// Consecutive rows of the index, with the cursors that make the walk resumable.
///
/// Every field follows from the cursor asked for and the rows returned. A segment that
/// reaches its boundary is therefore the same value on every later read, however far the
/// list has grown, and can be kept for good.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment<'a> {
    /// Position of the first row.
    pub base: u64,
    /// Cursor for the following segment.
    pub next: u64,
    /// `(next - base)` prefixes, back to back.
    pub rows: &'a [u8],
}

impl Segment<'_> {
    /// Whether these rows can never change: the segment is aligned and full, so every later
    /// read of the same cursor returns the same bytes.
    #[must_use]
    pub const fn is_sealed(&self) -> bool {
        self.base.is_multiple_of(SEGMENT_ROWS)
            && matches!(self.next.checked_sub(self.base), Some(SEGMENT_ROWS))
    }

    /// Whether the walk has reached the last row the server held: the segment stops short
    /// of its boundary. A list that ends exactly on a boundary is closed by the empty
    /// segment that follows it.
    #[must_use]
    pub const fn is_frontier(&self) -> bool {
        self.next < boundary_after(self.base)
    }

    /// Rows the index held when the segment was cut, which only the frontier segment says.
    #[must_use]
    pub const fn total(&self) -> Option<u64> {
        if self.is_frontier() {
            Some(self.next)
        } else {
            None
        }
    }
}

/// Cut the segment that starts at `since` and ends at the next segment boundary.
///
/// `since == total` is a wallet that is up to date: the segment is empty.
///
/// # Errors
/// [`FeedError::Ragged`] when `feed` is not whole rows, and [`FeedError::PastFrontier`] when
/// `since` is beyond the last row.
///
/// # Examples
/// ```
/// use howl_prefix_feed::{segment, PREFIX_BYTES};
/// let feed = vec![7u8; 10 * PREFIX_BYTES];
/// let tail = segment(&feed, 4)?;
/// assert_eq!((tail.base, tail.next, tail.total()), (4, 10, Some(10)));
/// assert!(segment(&feed, 10)?.rows.is_empty());
/// # Ok::<(), howl_prefix_feed::FeedError>(())
/// ```
pub fn segment(feed: &[u8], since: u64) -> Result<Segment<'_>, FeedError> {
    let total = row_count(feed)?;
    if since > total {
        return Err(FeedError::PastFrontier { since, total });
    }
    let next = boundary_after(since).min(total);
    let rows = feed
        .get(byte_offset(since)..byte_offset(next))
        .ok_or(FeedError::PastFrontier { since, total })?;
    Ok(Segment {
        base: since,
        next,
        rows,
    })
}

/// A position whose published prefix equals a candidate tag's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Match {
    /// Tree position, which is the row to fetch from the discovery table.
    pub position: u64,
    /// Index of the matching tag in the slice that was searched for.
    pub candidate: usize,
}

/// A wallet's copy of the index.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PrefixIndex {
    rows: Vec<u8>,
}

impl PrefixIndex {
    /// An empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reload an index a wallet stored.
    ///
    /// # Errors
    /// [`FeedError::Ragged`] when `rows` is not whole rows.
    pub fn from_bytes(rows: Vec<u8>) -> Result<Self, FeedError> {
        row_count(&rows)?;
        Ok(Self { rows })
    }

    /// The rows, back to back, for a wallet to store.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.rows
    }

    /// Rows held.
    #[must_use]
    pub fn len(&self) -> u64 {
        (self.rows.len() / PREFIX_BYTES) as u64
    }

    /// Whether no row is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Cursor to resume the walk from: the rows held, rounded down to
    /// [`RESUME_ALIGN_ROWS`], so the next segment re-reads the newest rows held and
    /// [`PrefixIndex::absorb`] compares them.
    #[must_use]
    pub fn resume_cursor(&self) -> u64 {
        self.len() / RESUME_ALIGN_ROWS * RESUME_ALIGN_ROWS
    }

    /// Append a segment's new rows, after checking the rows it re-reads. Returns the number
    /// of rows added.
    ///
    /// # Errors
    /// [`FeedError::Inconsistent`] for a segment whose cursors and rows disagree,
    /// [`FeedError::Gap`] when it starts beyond the rows held, and [`FeedError::Diverged`]
    /// when a re-read row differs. The index is unchanged on error.
    pub fn absorb(&mut self, segment: &Segment<'_>) -> Result<u64, FeedError> {
        let held = self.len();
        let carried = row_count(segment.rows)?;
        if segment.next.checked_sub(segment.base) != Some(carried)
            || segment.next > boundary_after(segment.base)
        {
            return Err(FeedError::Inconsistent {
                base: segment.base,
                next: segment.next,
                rows: carried,
            });
        }
        if segment.base > held {
            return Err(FeedError::Gap {
                base: segment.base,
                held,
            });
        }
        let overlap = (held - segment.base).min(carried);
        let (reread, fresh) = segment.rows.split_at(byte_offset(overlap));
        let mine = self
            .rows
            .get(byte_offset(segment.base)..byte_offset(segment.base + overlap))
            .unwrap_or_default();
        let differing = reread
            .as_chunks::<PREFIX_BYTES>()
            .0
            .iter()
            .zip(mine.as_chunks::<PREFIX_BYTES>().0)
            .position(|(theirs, ours)| theirs != ours);
        if let Some(row) = differing {
            return Err(FeedError::Diverged {
                position: segment.base + row as u64,
            });
        }
        self.rows.extend_from_slice(fresh);
        Ok(carried - overlap)
    }

    /// Every position at or after `from` whose prefix equals that of one of `tags`, in
    /// position order. Position 0 is the genesis leaf and is never reported.
    ///
    /// A tag carried by several notes matches at each of their positions.
    #[must_use]
    pub fn matches(&self, tags: &[[u8; TAG_BYTES]], from: u64) -> Vec<Match> {
        let mut wanted: HashMap<[u8; PREFIX_BYTES], Vec<usize>> = HashMap::new();
        for (candidate, tag) in tags.iter().enumerate() {
            wanted.entry(tag_prefix(tag)).or_default().push(candidate);
        }
        let first = from.max(1);
        let mut found = Vec::new();
        let rows = self.rows.get(byte_offset(first)..).unwrap_or_default();
        for (offset, row) in rows.as_chunks::<PREFIX_BYTES>().0.iter().enumerate() {
            let Some(candidates) = wanted.get(row) else {
                continue;
            };
            found.extend(candidates.iter().map(|candidate| Match {
                position: first + offset as u64,
                candidate: *candidate,
            }));
        }
        found
    }
}
