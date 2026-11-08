//! The file `luoto export` writes and `luoto import` reads: one tar archive holding an env's
//! config, what moves of its state, and the contents of its workspace and home volumes.
//!
//! ```text
//! manifest.json        always first: format, source instance and version, env, parts
//! env/config.toml      the env's own file
//! env/project.toml     the accepted luoto.toml, if any
//! env/state.json       what moves of its state (Moved)
//! volumes/work/…       the workspace volume, its root first
//! volumes/home/…       the home volume (left out by `--no-home`)
//! end.json             always last: each volume's entry and byte counts
//! ```
//!
//! Volume contents were written by the sandbox, and an archive may come from another machine:
//! both are untrusted. Every entry is decoded here (names capped, GNU long names only), checked
//! (a plain relative path, nothing under a symbolic link the stream made, hard links within the
//! volume, only files, folders, links and FIFOs) and written anew, never unpacked on the host:
//! the tar that a container unpacks into a volume is the one written here.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::{Read, Write};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use tar::{EntryType, Header};

/// The archive format this luoto writes and reads.
pub const FORMAT: u32 = 1;
const KIND: &str = "luoto-env";
const MANIFEST: &str = "manifest.json";
const END: &str = "end.json";
/// Cap on the small files: manifest, config, luoto.toml, state, end.
const MAX_FILE: u64 = 1 << 20;
/// Longest entry name or link target: Linux's PATH_MAX, and room for a part's folder.
const MAX_NAME: usize = 4096 + 64;
/// The most a tar header's name field holds; longer names go in a GNU long-name entry.
const NAME_FIELD: usize = 100;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Part {
    /// The env's file, `envs/<env>.toml`.
    Config,
    /// The accepted luoto.toml.
    Project,
    State,
    Work,
    Home,
}

impl Part {
    fn entry(self) -> &'static str {
        match self {
            Part::Config => "env/config.toml",
            Part::Project => "env/project.toml",
            Part::State => "env/state.json",
            Part::Work => "volumes/work/",
            Part::Home => "volumes/home/",
        }
    }

    /// The env's volume this part holds (`names::volume`'s `what`).
    pub fn volume(self) -> Option<&'static str> {
        match self {
            Part::Work => Some("work"),
            Part::Home => Some("home"),
            _ => None,
        }
    }

    /// For people.
    pub fn label(self) -> &'static str {
        match self {
            Part::Config => "config",
            Part::Project => "luoto.toml",
            Part::State => "state",
            Part::Work => "workspace",
            Part::Home => "home",
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Manifest {
    /// Always [`KIND`].
    pub kind: String,
    pub format: u32,
    /// The luoto version that wrote it.
    pub luoto: String,
    /// The instance it came from (`names::instance`).
    pub instance: String,
    pub env: String,
    /// RFC 3339.
    pub created: String,
    /// What it holds, in the order it holds it.
    pub parts: Vec<Part>,
}

impl Manifest {
    pub fn new(env: &str, parts: Vec<Part>) -> Self {
        Manifest {
            kind: KIND.into(),
            format: FORMAT,
            luoto: luoto_shared::VERSION.into(),
            instance: crate::names::instance().into(),
            env: env.into(),
            created: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            parts,
        }
    }

    /// The manifest in `json`: the kind and format are looked at before anything else, so an
    /// archive from a newer luoto says so rather than failing to parse.
    fn parse(json: &[u8]) -> Result<Self> {
        let v: serde_json::Value = serde_json::from_slice(json).map_err(|_| not_ours())?;
        if v["kind"].as_str() != Some(KIND) {
            return Err(not_ours());
        }
        let format = v["format"].as_u64().ok_or_else(not_ours)?;
        if format > u64::from(FORMAT) {
            bail!(
                "it is archive format {format}, from luoto {}; this luoto reads up to format \
                 {FORMAT}: upgrade it",
                crate::text::display(v["luoto"].as_str().unwrap_or("?"))
            );
        }
        let m: Manifest =
            serde_json::from_value(v).context("its manifest doesn't parse: not one luoto wrote")?;
        if m.format == 0 {
            return Err(not_ours());
        }
        let ordered = m.parts.windows(2).all(|w| w[0] < w[1]);
        let has = |p| m.parts.contains(&p);
        if !ordered || !has(Part::Config) || !has(Part::State) || !has(Part::Work) {
            bail!("its manifest lists parts no luoto writes");
        }
        crate::config::validate_name(&m.env).context("its manifest names no env")?;
        Ok(m)
    }
}

fn not_ours() -> anyhow::Error {
    anyhow!("not an env archive (`luoto export` writes them)")
}

/// What moves of an env's state (`state.rs`); its subnet, vault token, CA and the stamps of
/// what `up` rebuilds stay behind, and the new env gets its own.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Moved {
    /// Where the home volume is mounted in the dev container.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home: Option<String>,
    /// The folder, or the remote, is in the workspace volume already.
    pub seeded: bool,
    /// Repos in the workspace volume.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub repos: BTreeSet<String>,
    /// Repos answered as public, needing no credential (`repos.rs`).
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub public_repos: BTreeSet<String>,
    /// The sha256 of the luoto.toml text the user declined (`project.rs`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declined_project: Option<String>,
}

impl Moved {
    /// Refuse what no export writes: each value reaches a mount, a file name or a prompt.
    pub fn check(&self) -> Result<()> {
        if let Some(h) = &self.home {
            check_home(h)?;
        }
        for r in &self.repos {
            crate::repos::check_name(r).context("its state's repos")?;
        }
        for k in &self.public_repos {
            let ok = !k.is_empty() && k.len() <= 512 && k.bytes().all(|b| b.is_ascii_graphic());
            if !ok {
                bail!(
                    "its state names a repo as `{}`, which luoto never writes",
                    crate::text::display(k)
                );
            }
        }
        if let Some(sha) = &self.declined_project
            && !(sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            bail!("its state's declined luoto.toml is not a sha256");
        }
        Ok(())
    }
}

/// The dev user's home as a mount target: an absolute path of plain names, with nothing the
/// runtime's `-v` reads as a separator, and none of luoto's own folders.
fn check_home(h: &str) -> Result<()> {
    let plain = h.len() <= 255
        && h.starts_with('/')
        && h.chars()
            .all(|c| !c.is_control() && !crate::text::is_format(c) && c != ':' && c != ',')
        && h[1..]
            .split('/')
            .all(|c| !c.is_empty() && c != "." && c != "..");
    let reserved = ["/workspace", "/opt/luoto", "/run", "/proc", "/sys", "/dev"]
        .iter()
        .any(|r| h == *r || h.starts_with(&format!("{r}/")));
    if !plain || reserved {
        bail!(
            "its state's home `{}` is not a home folder",
            crate::text::display(h)
        );
    }
    Ok(())
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Count {
    pub entries: u64,
    /// Bytes of file data.
    pub bytes: u64,
}

/// The last entry: what an archive cut short would lack.
#[derive(Serialize, Deserialize, Debug, Default, PartialEq)]
struct End {
    volumes: BTreeMap<Part, Count>,
}

/// The kinds of entry that move.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    File,
    Dir,
    Symlink,
    Hardlink,
    Fifo,
}

impl Kind {
    fn of(t: u8) -> Option<Self> {
        Some(match t {
            b'0' | b'\0' | b'7' => Kind::File,
            b'5' => Kind::Dir,
            b'2' => Kind::Symlink,
            b'1' => Kind::Hardlink,
            b'6' => Kind::Fifo,
            _ => return None,
        })
    }

    fn entry_type(self) -> EntryType {
        match self {
            Kind::File => EntryType::Regular,
            Kind::Dir => EntryType::Directory,
            Kind::Symlink => EntryType::Symlink,
            Kind::Hardlink => EntryType::Link,
            Kind::Fifo => EntryType::Fifo,
        }
    }
}

/// An entry as decoded here: its whole name and link, and the metadata that moves.
struct Item<'a, R: Read> {
    name: Vec<u8>,
    link: Option<Vec<u8>>,
    kind: Kind,
    mode: u32,
    uid: u64,
    gid: u64,
    mtime: u64,
    size: u64,
    data: tar::Entry<'a, R>,
}

/// Entries of a tar stream, with GNU long names and links read here (capped) and anything
/// else that describes another entry refused: tar extensions are where parsers disagree.
pub struct Decoder<'a, R: Read> {
    entries: tar::Entries<'a, R>,
}

impl<'a, R: Read> Decoder<'a, R> {
    pub fn new(archive: &'a mut tar::Archive<R>) -> Result<Self> {
        Ok(Decoder {
            entries: archive.entries()?.raw(true),
        })
    }

    fn next(&mut self) -> Result<Option<Item<'a, R>>> {
        let (mut long_name, mut long_link) = (None, None);
        loop {
            let Some(entry) = self.entries.next() else {
                if long_name.is_some() || long_link.is_some() {
                    bail!("the archive ends inside an entry");
                }
                return Ok(None);
            };
            let mut entry = entry.context("read the archive")?;
            let t = entry.header().entry_type().as_byte();
            if t == b'L' || t == b'K' {
                let slot = if t == b'L' {
                    &mut long_name
                } else {
                    &mut long_link
                };
                if slot.is_some() {
                    bail!("an entry has two long names");
                }
                *slot = Some(long(&mut entry)?);
                continue;
            }
            let h = entry.header();
            let name = match long_name {
                Some(n) => n,
                None => h.path_bytes().into_owned(),
            };
            let kind = Kind::of(t).with_context(|| {
                format!(
                    "{}: entries of type `{}` don't move (only files, folders, links and FIFOs)",
                    show(&name),
                    t.escape_ascii()
                )
            })?;
            let link = match kind {
                Kind::Symlink | Kind::Hardlink => Some(match long_link {
                    Some(l) => l,
                    None => h
                        .link_name_bytes()
                        .map(std::borrow::Cow::into_owned)
                        .unwrap_or_default(),
                }),
                _ if long_link.is_some() => bail!("{}: a link name on no link", show(&name)),
                _ => None,
            };
            let size = if kind == Kind::File {
                h.entry_size()?
            } else {
                0
            };
            let (mode, uid, gid, mtime) = (h.mode()? & 0o7777, h.uid()?, h.gid()?, h.mtime()?);
            return Ok(Some(Item {
                name,
                link,
                kind,
                mode,
                uid,
                gid,
                mtime,
                size,
                data: entry,
            }));
        }
    }
}

/// A GNU long name or link: its data, without the NUL that ends it.
fn long<R: Read>(entry: &mut tar::Entry<'_, R>) -> Result<Vec<u8>> {
    if entry.size() > MAX_NAME as u64 + 1 {
        bail!("a name longer than {MAX_NAME} bytes");
    }
    let mut v = Vec::new();
    entry.read_to_end(&mut v)?;
    while v.last() == Some(&0) {
        v.pop();
    }
    if v.is_empty() || v.contains(&0) {
        bail!("an empty or malformed long name");
    }
    Ok(v)
}

/// A name for messages: escaped, since a volume's names are the sandbox's.
fn show(name: &[u8]) -> String {
    crate::text::display(&String::from_utf8_lossy(name))
}

/// `name` as a path in a volume: plain names joined by `/`, with no `.`, `..` or empty one,
/// past a leading `./` (and a trailing `/` on a folder). Empty for the volume's root. Only
/// `/` separates: a volume is a Linux filesystem, where `\` and `:` are parts of a name.
fn relative(name: &[u8], dir: bool) -> Result<Vec<u8>> {
    let mut n = name;
    if n == b"." {
        n = b"";
    } else if let Some(rest) = n.strip_prefix(b"./") {
        n = rest;
    }
    if dir && let Some(rest) = n.strip_suffix(b"/") {
        n = rest;
    }
    if n.is_empty() {
        return Ok(Vec::new());
    }
    if n.contains(&0)
        || n.split(|b| *b == b'/')
            .any(|c| c.is_empty() || c == b"." || c == b"..")
    {
        bail!("{}: not a plain path in the volume", show(name));
    }
    Ok(n.to_vec())
}

/// The name a volume's entry has in the archive, under its part's folder.
fn outer_name(part: Part, rel: &[u8], dir: bool) -> Vec<u8> {
    let mut n = part.entry().as_bytes().to_vec();
    n.extend_from_slice(rel);
    if dir && !rel.is_empty() {
        n.push(b'/');
    }
    n
}

/// The name a volume's entry has in the stream unpacked into it: `./` for the root.
fn inner_name(rel: &[u8], dir: bool) -> Vec<u8> {
    if rel.is_empty() {
        return b"./".to_vec();
    }
    let mut n = rel.to_vec();
    if dir {
        n.push(b'/');
    }
    n
}

/// One volume's entries as they are checked: its root comes first, and what the stream made a
/// symbolic link is never written through.
#[derive(Default)]
struct Volume {
    symlinks: HashSet<Vec<u8>>,
    count: Count,
}

/// An entry's checked path in its volume, and its link: a hard link's target in the volume, a
/// symbolic link's target as it is (in the env, it may point anywhere).
struct Checked {
    rel: Vec<u8>,
    link: Option<Vec<u8>>,
}

impl Volume {
    fn check(&mut self, kind: Kind, name: &[u8], link: Option<&[u8]>) -> Result<Checked> {
        let rel = relative(name, kind == Kind::Dir)?;
        match (self.count.entries, rel.is_empty()) {
            (0, true) if kind == Kind::Dir => {}
            (0, _) => bail!("a volume's first entry is not its root folder"),
            (_, true) => bail!("a volume's root comes twice"),
            _ => {}
        }
        self.through_link(&rel, true)?;
        let link = match (kind, link) {
            (Kind::Symlink, Some(l)) if !l.is_empty() && l.len() <= MAX_NAME => {
                self.symlinks.insert(rel.clone());
                Some(l.to_vec())
            }
            (Kind::Hardlink, Some(l)) => {
                let target = relative(l, false)?;
                if target.is_empty() {
                    bail!("{}: a hard link to the volume's root", show(name));
                }
                self.through_link(&target, false)?;
                Some(target)
            }
            (Kind::Symlink | Kind::Hardlink, _) => bail!("{}: a link to nothing", show(name)),
            _ => None,
        };
        self.count.entries += 1;
        Ok(Checked { rel, link })
    }

    /// Refuse a path below a symbolic link the stream made, or (`itself`) that is one:
    /// unpacking it would follow the link out of the volume.
    fn through_link(&self, rel: &[u8], itself: bool) -> Result<()> {
        let below = rel
            .iter()
            .enumerate()
            .filter(|(_, b)| **b == b'/')
            .any(|(i, _)| self.symlinks.contains(&rel[..i]));
        if below || (itself && self.symlinks.contains(rel)) {
            bail!("{}: under or over a symbolic link", show(rel));
        }
        Ok(())
    }
}

/// Bytes read, each read told to `tick`.
struct Counted<'t, R> {
    inner: R,
    n: u64,
    tick: &'t mut dyn FnMut(u64),
}

impl<R: Read> Read for Counted<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.n += n as u64;
        (self.tick)(n as u64);
        Ok(n)
    }
}

/// `value` in a header's name or link field, after a GNU long-name entry (`kind` `L` or `K`)
/// when it is longer than the field.
fn put_name<W: Write>(
    out: &mut tar::Builder<W>,
    kind: u8,
    value: &[u8],
    field: &mut [u8; NAME_FIELD],
) -> Result<()> {
    let n = value.len().min(NAME_FIELD);
    field[..n].copy_from_slice(&value[..n]);
    if value.len() > NAME_FIELD {
        let mut h = Header::new_gnu();
        h.as_old_mut().name[..13].copy_from_slice(b"././@LongLink");
        h.set_mode(0o644);
        h.set_uid(0);
        h.set_gid(0);
        h.set_mtime(0);
        h.set_size(value.len() as u64 + 1);
        h.set_entry_type(EntryType::new(kind));
        h.set_cksum();
        out.append(&h, value.chain(&[0u8][..]))?;
    }
    Ok(())
}

/// Write `item` anew as `name` (and `link`): a fresh header with only the metadata that moves,
/// then its data. Its data bytes.
fn put<W: Write, R: Read>(
    out: &mut tar::Builder<W>,
    item: &mut Item<'_, R>,
    name: &[u8],
    link: Option<&[u8]>,
    tick: &mut dyn FnMut(u64),
) -> Result<u64> {
    let mut h = Header::new_gnu();
    h.set_entry_type(item.kind.entry_type());
    h.set_mode(item.mode);
    h.set_uid(item.uid);
    h.set_gid(item.gid);
    h.set_mtime(item.mtime);
    h.set_size(item.size);
    put_name(out, b'L', name, &mut h.as_old_mut().name)?;
    if let Some(l) = link {
        put_name(out, b'K', l, &mut h.as_old_mut().linkname)?;
    }
    h.set_cksum();
    let size = item.size;
    let mut data = Counted {
        inner: (&mut item.data).take(size),
        n: 0,
        tick,
    };
    out.append(&h, &mut data)?;
    if data.n != size {
        bail!("the archive ends inside {}", show(name));
    }
    Ok(size)
}

/// A small file of luoto's own.
fn put_file<W: Write>(out: &mut tar::Builder<W>, name: &str, data: &[u8]) -> Result<()> {
    let mut h = Header::new_gnu();
    h.set_entry_type(EntryType::Regular);
    h.set_mode(0o600);
    h.set_uid(0);
    h.set_gid(0);
    h.set_mtime(chrono::Utc::now().timestamp().max(0) as u64);
    h.set_size(data.len() as u64);
    put_name(out, b'L', name.as_bytes(), &mut h.as_old_mut().name)?;
    h.set_cksum();
    out.append(&h, data)?;
    Ok(())
}

/// The data of a small file of luoto's own named `name`, which `item` must be.
fn read_file<R: Read>(item: Option<Item<'_, R>>, name: &str) -> Result<Vec<u8>> {
    let mut item = item.with_context(|| format!("the archive ends before {name}"))?;
    if item.name != name.as_bytes() || item.kind != Kind::File {
        bail!("{} where {name} belongs", show(&item.name));
    }
    if item.size > MAX_FILE {
        bail!("{name} is larger than {MAX_FILE} bytes");
    }
    let mut v = Vec::with_capacity(item.size as usize);
    (&mut item.data).take(item.size).read_to_end(&mut v)?;
    if v.len() as u64 != item.size {
        bail!("the archive ends inside {name}");
    }
    Ok(v)
}

/// Writes an archive: the manifest, then each of its parts in order, then the end.
pub struct Writer<W: Write> {
    out: tar::Builder<W>,
    parts: std::vec::IntoIter<Part>,
    end: End,
}

impl<W: Write> Writer<W> {
    pub fn new(out: W, manifest: &Manifest) -> Result<Self> {
        let mut out = tar::Builder::new(out);
        put_file(&mut out, MANIFEST, &serde_json::to_vec_pretty(manifest)?)?;
        Ok(Writer {
            out,
            parts: manifest.parts.clone().into_iter(),
            end: End::default(),
        })
    }

    fn next_part(&mut self, part: Part) -> Result<()> {
        match self.parts.next() {
            Some(p) if p == part => Ok(()),
            _ => bail!("{} is not the archive's next part", part.label()),
        }
    }

    pub fn file(&mut self, part: Part, data: &[u8]) -> Result<()> {
        self.next_part(part)?;
        put_file(&mut self.out, part.entry(), data)
    }

    /// The volume of `part` from `src`, a tar stream of its contents (`tar -c` in a container
    /// that mounts it), each entry checked and written under the part's folder. `tick` gets
    /// the data bytes as they go.
    pub fn volume(
        &mut self,
        part: Part,
        src: impl Read,
        tick: &mut dyn FnMut(u64),
    ) -> Result<Count> {
        self.next_part(part)?;
        let mut archive = tar::Archive::new(src);
        let mut vol = Volume::default();
        {
            let mut dec = Decoder::new(&mut archive)?;
            while let Some(mut item) = dec.next()? {
                let c = vol.check(item.kind, &item.name, item.link.as_deref())?;
                let name = outer_name(part, &c.rel, item.kind == Kind::Dir);
                let link = match item.kind {
                    Kind::Hardlink => c.link.map(|t| outer_name(part, &t, false)),
                    _ => c.link,
                };
                vol.count.bytes += put(&mut self.out, &mut item, &name, link.as_deref(), tick)?;
            }
        }
        if vol.count.entries == 0 {
            bail!("the {} volume gave no entries", part.label());
        }
        // The rest of the stream (its end and padding), so the tar writing it finishes.
        std::io::copy(&mut archive.into_inner(), &mut std::io::sink())?;
        self.end.volumes.insert(part, vol.count);
        Ok(vol.count)
    }

    /// The end entry; the archive's writer, flushed.
    pub fn finish(mut self) -> Result<W> {
        if let Some(p) = self.parts.next() {
            bail!("the archive's {} is missing", p.label());
        }
        put_file(&mut self.out, END, &serde_json::to_vec_pretty(&self.end)?)?;
        let mut w = self.out.into_inner()?;
        w.flush()?;
        Ok(w)
    }
}

/// Where `read_volumes` sends each volume's contents: a tar stream to unpack into it.
pub trait Sink {
    fn open(&mut self, part: Part) -> Result<Box<dyn Write>>;
    /// `part`'s stream `w` is complete: the sink checks that it was unpacked.
    fn close(&mut self, part: Part, w: Box<dyn Write>) -> Result<()>;
}

/// What an archive holds before its volumes.
#[derive(Debug)]
pub struct Head {
    pub manifest: Manifest,
    pub config: String,
    pub project: Option<String>,
    pub state: Moved,
}

/// The manifest and the small files of the archive `dec` reads, checked; the volumes follow.
pub fn read_head<R: Read>(dec: &mut Decoder<'_, R>) -> Result<Head> {
    let first = dec.next().map_err(|_| not_ours())?.ok_or_else(not_ours)?;
    if first.name != MANIFEST.as_bytes() {
        return Err(not_ours());
    }
    let manifest = Manifest::parse(&read_file(Some(first), MANIFEST)?)?;
    let mut text = |part: Part| -> Result<Option<String>> {
        if !manifest.parts.contains(&part) {
            return Ok(None);
        }
        let bytes = read_file(dec.next()?, part.entry())?;
        String::from_utf8(bytes)
            .map(Some)
            .with_context(|| format!("{} is not UTF-8", part.entry()))
    };
    let config = text(Part::Config)?.unwrap_or_default();
    let project = text(Part::Project)?;
    let state: Moved = serde_json::from_str(&text(Part::State)?.unwrap_or_default())
        .context("its state doesn't parse")?;
    state.check()?;
    Ok(Head {
        manifest,
        config,
        project,
        state,
    })
}

/// The volumes of the archive `dec` reads (after [`read_head`]), each entry checked and written
/// anew to `sink`, then its end, which must match what came. `tick` gets data bytes as they go.
pub fn read_volumes<R: Read>(
    dec: &mut Decoder<'_, R>,
    manifest: &Manifest,
    sink: &mut dyn Sink,
    tick: &mut dyn FnMut(u64),
) -> Result<()> {
    let mut item = dec.next()?;
    let mut seen = BTreeMap::new();
    for part in manifest
        .parts
        .iter()
        .copied()
        .filter(|p| p.volume().is_some())
    {
        let prefix = part.entry().as_bytes();
        let mut vol = Volume::default();
        let mut out = tar::Builder::new(sink.open(part)?);
        while let Some(mut it) = item.take_if(|it| it.name.starts_with(prefix)) {
            let link = match (it.kind, &it.link) {
                (Kind::Hardlink, Some(l)) => Some(l.strip_prefix(prefix).with_context(|| {
                    format!("{}: a hard link out of its volume", show(&it.name))
                })?),
                (_, l) => l.as_deref(),
            };
            let c = vol.check(it.kind, &it.name[prefix.len()..], link)?;
            let name = inner_name(&c.rel, it.kind == Kind::Dir);
            vol.count.bytes += put(&mut out, &mut it, &name, c.link.as_deref(), tick)?;
            item = dec.next()?;
        }
        if vol.count.entries == 0 {
            bail!("the archive has no {}", part.label());
        }
        let mut w = out.into_inner()?;
        w.flush()?;
        sink.close(part, w)?;
        seen.insert(part, vol.count);
    }
    let end: End = serde_json::from_slice(
        &read_file(item, END)
            .context("the archive is incomplete (cut short in a copy?): export the env again")?,
    )
    .context("its end doesn't parse")?;
    if end.volumes != seen {
        bail!("the archive is incomplete: its end counts other entries than it holds");
    }
    if dec.next()?.is_some() {
        bail!("the archive has entries after its end");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// A raw entry, for streams no well-behaved writer makes.
    fn raw(out: &mut tar::Builder<Vec<u8>>, t: u8, name: &[u8], link: &[u8], data: &[u8]) {
        let mut h = Header::new_gnu();
        h.set_entry_type(EntryType::new(t));
        h.set_mode(0o644);
        h.set_uid(1000);
        h.set_gid(1000);
        h.set_mtime(1_700_000_000);
        h.set_size(data.len() as u64);
        put_name(out, b'L', name, &mut h.as_old_mut().name).unwrap();
        if !link.is_empty() {
            put_name(out, b'K', link, &mut h.as_old_mut().linkname).unwrap();
        }
        h.set_cksum();
        out.append(&h, data).unwrap();
    }

    /// An entry to write: type, name, link, data.
    type Raw<'a> = (u8, &'a [u8], &'a [u8], &'a [u8]);
    /// An entry read: type, name, link, uid, mode, data.
    type Got = (u8, Vec<u8>, Vec<u8>, u64, u32, Vec<u8>);

    /// A volume's stream as busybox `tar -c -C /v .` writes it, with `entries` after its root.
    fn volume(entries: &[Raw]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        raw(&mut b, b'5', b"./", b"", b"");
        for (t, name, link, data) in entries {
            raw(&mut b, *t, name, link, data);
        }
        b.into_inner().unwrap()
    }

    #[derive(Default, Clone)]
    struct Memory {
        streams: Rc<RefCell<BTreeMap<Part, Vec<u8>>>>,
        open: Option<Part>,
    }

    struct Into(Rc<RefCell<BTreeMap<Part, Vec<u8>>>>, Part);

    impl Write for Into {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .borrow_mut()
                .entry(self.1)
                .or_default()
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Sink for Memory {
        fn open(&mut self, part: Part) -> Result<Box<dyn Write>> {
            assert!(self.open.replace(part).is_none());
            Ok(Box::new(Into(self.streams.clone(), part)))
        }
        fn close(&mut self, part: Part, _: Box<dyn Write>) -> Result<()> {
            assert_eq!(self.open.take(), Some(part));
            Ok(())
        }
    }

    fn state() -> Moved {
        Moved {
            home: Some("/home/ubuntu".into()),
            seeded: true,
            repos: ["api".to_string()].into(),
            public_repos: ["github:acme/lib".to_string()].into(),
            declined_project: None,
        }
    }

    fn export(work: &[u8], home: Option<&[u8]>) -> Vec<u8> {
        let mut parts = vec![Part::Config, Part::Project, Part::State, Part::Work];
        parts.extend(home.map(|_| Part::Home));
        let m = Manifest::new("web", parts);
        let mut w = Writer::new(Vec::new(), &m).unwrap();
        w.file(Part::Config, b"presets = [\"npm\"]\n").unwrap();
        w.file(Part::Project, b"ports = [5173]\n").unwrap();
        w.file(Part::State, &serde_json::to_vec(&state()).unwrap())
            .unwrap();
        w.volume(Part::Work, work, &mut |_| {}).unwrap();
        if let Some(h) = home {
            w.volume(Part::Home, h, &mut |_| {}).unwrap();
        }
        w.finish().unwrap()
    }

    fn import(bytes: &[u8]) -> Result<(Head, BTreeMap<Part, Vec<u8>>)> {
        let mut archive = tar::Archive::new(bytes);
        let mut dec = Decoder::new(&mut archive)?;
        let head = read_head(&mut dec)?;
        let mut sink = Memory::default();
        read_volumes(&mut dec, &head.manifest, &mut sink, &mut |_| {})?;
        let streams = sink.streams.borrow().clone();
        Ok((head, streams))
    }

    /// Each entry of a stream, through the tar crate.
    fn entries(stream: &[u8]) -> Vec<Got> {
        let mut a = tar::Archive::new(stream);
        a.entries()
            .unwrap()
            .map(|e| {
                let mut e = e.unwrap();
                let h = e.header().clone();
                let mut data = Vec::new();
                e.read_to_end(&mut data).unwrap();
                (
                    h.entry_type().as_byte(),
                    e.path_bytes().into_owned(),
                    e.link_name_bytes()
                        .map(|l| l.into_owned())
                        .unwrap_or_default(),
                    h.uid().unwrap(),
                    h.mode().unwrap(),
                    data,
                )
            })
            .collect()
    }

    fn import_err(bytes: &[u8]) -> String {
        format!("{:#}", import(bytes).unwrap_err())
    }

    #[test]
    fn an_export_reads_back_as_written() {
        let long = [b"./deep/".as_slice(), &[b'n'; 180]].concat();
        let odd = "./caf\u{e9} a\\b:c".as_bytes();
        let work = volume(&[
            (b'5', b"./deep/", b"", b""),
            (b'0', &long, b"", b"long"),
            (b'0', odd, b"", b"odd"),
            (b'0', &[b'.', b'/', 0xff, 0xfe], b"", b"not utf-8"),
            (b'2', b"./abs", b"/etc/hosts", b""),
            (b'2', b"./up", b"../../outside", b""),
            (b'1', b"./hard", b"./caf\xc3\xa9 a\\b:c", b""),
            (b'6', b"./fifo", b"", b""),
        ]);
        let home = volume(&[(b'0', b"./.bashrc", b"", b"export X=1\n")]);
        let (head, streams) = import(&export(&work, Some(&home))).unwrap();

        let m = &head.manifest;
        assert_eq!(
            (m.kind.as_str(), m.format, m.env.as_str()),
            (KIND, FORMAT, "web")
        );
        assert_eq!(m.instance, crate::names::instance());
        assert_eq!(m.luoto, luoto_shared::VERSION);
        assert_eq!(head.config, "presets = [\"npm\"]\n");
        assert_eq!(head.project.as_deref(), Some("ports = [5173]\n"));
        assert_eq!(head.state, state());

        let w = entries(&streams[&Part::Work]);
        let names: Vec<&[u8]> = w.iter().map(|e| e.1.as_slice()).collect();
        let long_inner = [b"deep/".as_slice(), &[b'n'; 180]].concat();
        assert_eq!(
            names,
            [
                b"./".as_slice(),
                b"deep/",
                &long_inner,
                "caf\u{e9} a\\b:c".as_bytes(),
                &[0xff, 0xfe],
                b"abs",
                b"up",
                b"hard",
                b"fifo"
            ]
        );
        // Owners, modes, data and link targets as they were; a symbolic link's target is
        // the env's business.
        assert!(w.iter().all(|e| e.3 == 1000 && e.4 == 0o644));
        assert_eq!(w[2].5, b"long");
        assert_eq!(w[5].2, b"/etc/hosts");
        assert_eq!(w[6].2, b"../../outside");
        assert_eq!(
            (w[7].0, w[7].2.as_slice()),
            (b'1', "caf\u{e9} a\\b:c".as_bytes())
        );
        assert_eq!(w[8].0, b'6');
        assert_eq!(entries(&streams[&Part::Home])[1].5, b"export X=1\n");
    }

    #[test]
    fn the_home_is_left_out_when_asked() {
        let (head, streams) = import(&export(&volume(&[]), None)).unwrap();
        assert!(!head.manifest.parts.contains(&Part::Home));
        assert_eq!(streams.keys().copied().collect::<Vec<_>>(), [Part::Work]);
    }

    #[test]
    fn archive_entries_live_under_their_parts() {
        let work = volume(&[(b'0', b"./a/b", b"", b"x")]);
        let bytes = export(&work, None);
        let names: Vec<String> = entries(&bytes)
            .into_iter()
            .map(|e| String::from_utf8(e.1).unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "manifest.json",
                "env/config.toml",
                "env/project.toml",
                "env/state.json",
                "volumes/work/",
                "volumes/work/a/b",
                "end.json"
            ]
        );
    }

    #[test]
    fn names_are_plain_paths_in_the_volume() {
        for (name, dir, want) in [
            (b"./".as_slice(), true, b"".as_slice()),
            (b".", true, b""),
            (b"./a/b", false, b"a/b"),
            (b"a/b/", true, b"a/b"),
            (b"a\\..\\b", false, b"a\\..\\b"),
        ] {
            assert_eq!(relative(name, dir).unwrap(), want, "{}", show(name));
        }
        for name in [
            b"/etc/passwd".as_slice(),
            b"../x",
            b"a/../b",
            b"a/..",
            b"a//b",
            b"a/./b",
            b"./../x",
            b"a/b/",
            b"a\0b",
        ] {
            assert!(relative(name, false).is_err(), "{}", show(name));
        }
    }

    #[test]
    fn a_crafted_volume_is_refused() {
        let link = (b'2', b"./a".as_slice(), b"/etc".as_slice(), b"".as_slice());
        let cases: &[(&str, Vec<u8>, &str)] = &[
            (
                "traversal",
                volume(&[(b'0', b"./../../etc/x", b"", b"")]),
                "not a plain path",
            ),
            (
                "absolute",
                volume(&[(b'0', b"/etc/x", b"", b"")]),
                "not a plain path",
            ),
            (
                "through a link",
                volume(&[link, (b'0', b"./a/passwd", b"", b"")]),
                "symbolic link",
            ),
            (
                "over a link",
                volume(&[link, (b'5', b"./a/", b"", b"")]),
                "symbolic link",
            ),
            (
                "hard link out",
                volume(&[(b'1', b"./h", b"../../etc/shadow", b"")]),
                "not a plain path",
            ),
            (
                "hard link through a link",
                volume(&[link, (b'1', b"./h", b"./a/shadow", b"")]),
                "symbolic link",
            ),
            (
                "link to nothing",
                volume(&[(b'2', b"./a", b"", b"")]),
                "a link to nothing",
            ),
            (
                "device",
                volume(&[(b'3', b"./tty", b"", b"")]),
                "don't move",
            ),
            (
                "pax",
                volume(&[(b'x', b"./pax", b"", b"30 path=../../../etc/passwd\n")]),
                "don't move",
            ),
            (
                "root later",
                volume(&[(b'5', b"./", b"", b"")]),
                "root comes twice",
            ),
        ];
        for (what, work, says) in cases {
            let mut w = Writer::new(Vec::new(), &Manifest::new("web", vec![Part::Work])).unwrap();
            let e = w
                .volume(Part::Work, work.as_slice(), &mut |_| {})
                .unwrap_err();
            assert!(format!("{e:#}").contains(says), "{what}: {e:#}");
        }
        let mut no_root = tar::Builder::new(Vec::new());
        raw(&mut no_root, b'0', b"./a", b"", b"x");
        let mut w = Writer::new(Vec::new(), &Manifest::new("web", vec![Part::Work])).unwrap();
        let e = w
            .volume(
                Part::Work,
                no_root.into_inner().unwrap().as_slice(),
                &mut |_| {},
            )
            .unwrap_err();
        assert!(e.to_string().contains("root folder"), "{e}");
    }

    /// An archive as `export` writes it up to its volumes, then `rest`.
    fn crafted(rest: impl FnOnce(&mut tar::Builder<Vec<u8>>)) -> Vec<u8> {
        let m = Manifest::new("web", vec![Part::Config, Part::State, Part::Work]);
        let mut b = tar::Builder::new(Vec::new());
        put_file(&mut b, MANIFEST, &serde_json::to_vec(&m).unwrap()).unwrap();
        put_file(&mut b, "env/config.toml", b"").unwrap();
        put_file(&mut b, "env/state.json", b"{\"seeded\":true}").unwrap();
        rest(&mut b);
        b.into_inner().unwrap()
    }

    #[test]
    fn a_crafted_archive_is_refused_before_anything_is_unpacked() {
        let end = |b: &mut tar::Builder<Vec<u8>>, n: u64| {
            let end = End {
                volumes: [(
                    Part::Work,
                    Count {
                        entries: n,
                        bytes: 0,
                    },
                )]
                .into(),
            };
            put_file(b, END, &serde_json::to_vec(&end).unwrap()).unwrap();
        };
        let ok = crafted(|b| {
            raw(b, b'5', b"volumes/work/", b"", b"");
            raw(b, b'5', b"volumes/work/a/", b"", b"");
            end(b, 2);
        });
        assert!(import(&ok).is_ok(), "{}", import_err(&ok));
        for (what, bytes, says) in [
            (
                "traversal",
                crafted(|b| {
                    raw(b, b'5', b"volumes/work/", b"", b"");
                    raw(b, b'0', b"volumes/work/../../x", b"", b"");
                }),
                "not a plain path",
            ),
            (
                "hard link to another part",
                crafted(|b| {
                    raw(b, b'5', b"volumes/work/", b"", b"");
                    raw(b, b'1', b"volumes/work/h", b"env/config.toml", b"");
                }),
                "out of its volume",
            ),
            (
                "no root",
                crafted(|b| raw(b, b'0', b"volumes/work/a", b"", b"x")),
                "root folder",
            ),
            (
                "no end",
                crafted(|b| raw(b, b'5', b"volumes/work/", b"", b"")),
                "incomplete",
            ),
            (
                "an end that counts more",
                crafted(|b| {
                    raw(b, b'5', b"volumes/work/", b"", b"");
                    end(b, 9);
                }),
                "incomplete",
            ),
            (
                "something after the end",
                crafted(|b| {
                    raw(b, b'5', b"volumes/work/", b"", b"");
                    end(b, 1);
                    raw(b, b'0', b"volumes/home/x", b"", b"");
                }),
                "after its end",
            ),
            (
                "a part elsewhere",
                crafted(|b| {
                    raw(b, b'5', b"volumes/work/", b"", b"");
                    raw(b, b'0', b"volumes/workx", b"", b"");
                }),
                "where end.json belongs",
            ),
            (
                "a huge long name",
                crafted(|b| {
                    raw(b, b'5', b"volumes/work/", b"", b"");
                    raw(b, b'0', &vec![b'a'; MAX_NAME + 10], b"", b"");
                }),
                "longer than",
            ),
        ] {
            let e = import_err(&bytes);
            assert!(e.contains(says), "{what}: {e}");
        }
    }

    #[test]
    fn only_an_archive_luoto_wrote_in_a_format_it_reads_is_imported() {
        assert!(import_err(b"plain text, not a tar").contains("not an env archive"));
        let mut other = tar::Builder::new(Vec::new());
        put_file(&mut other, "README", b"hi").unwrap();
        assert!(import_err(&other.into_inner().unwrap()).contains("not an env archive"));

        let with = |m: serde_json::Value| {
            let mut b = tar::Builder::new(Vec::new());
            put_file(&mut b, MANIFEST, m.to_string().as_bytes()).unwrap();
            import_err(&b.into_inner().unwrap())
        };
        let mut m = serde_json::to_value(Manifest::new("web", vec![Part::Config])).unwrap();
        m["format"] = (FORMAT + 1).into();
        m["parts"] = serde_json::json!(["config", "state", "work", "somethingnew"]);
        let e = with(m.clone());
        assert!(
            e.contains("upgrade") && e.contains(&format!("format {}", FORMAT + 1)),
            "{e}"
        );
        m["format"] = FORMAT.into();
        m["kind"] = "something-else".into();
        assert!(with(m.clone()).contains("not an env archive"));
        m["kind"] = KIND.into();
        m["parts"] = serde_json::json!(["config", "state"]);
        assert!(with(m.clone()).contains("parts no luoto writes"));
        m["parts"] = serde_json::json!(["state", "config", "work"]);
        assert!(with(m.clone()).contains("parts no luoto writes"));
        m["parts"] = serde_json::json!(["config", "state", "work"]);
        m["env"] = "../x".into();
        assert!(with(m).contains("names no env"));
    }

    #[test]
    fn the_state_that_moves_is_checked() {
        assert!(state().check().is_ok());
        for home in [
            "home/dev",
            "/",
            "/home/../etc",
            "/home/dev:/etc",
            "/home/dev,ro",
            "/workspace",
            "/opt/luoto/x",
            "/run/luoto",
        ] {
            let s = Moved {
                home: Some(home.into()),
                ..state()
            };
            assert!(s.check().is_err(), "{home}");
        }
        for bad in [
            Moved {
                repos: ["../x".to_string()].into(),
                ..state()
            },
            Moved {
                public_repos: ["github:a b".to_string()].into(),
                ..state()
            },
            Moved {
                declined_project: Some("nope".into()),
                ..state()
            },
        ] {
            assert!(bad.check().is_err(), "{bad:?}");
        }
        assert!(serde_json::from_str::<Moved>(r#"{"seeded":true,"octet":3}"#).is_err());
    }
}
