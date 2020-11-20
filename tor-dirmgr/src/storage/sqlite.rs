//! Net document storage backed by sqlite3. DOCDOC say more

// XXXX Does this belong in dirmgr instead of netdir? I think it might.

use crate::docmeta::ConsensusMeta;
use crate::storage::InputString;
use crate::{Error, Result};

use tor_llcrypto::pk::rsa::RSAIdentity;
use tor_netdoc::doc::authcert::{AuthCert, AuthCertKeyIds};
use tor_netdoc::doc::microdesc::{MDDigest, Microdesc};
use tor_netdoc::doc::netstatus::{self, MDConsensus};

use std::collections::HashMap;
use std::convert::TryInto;
use std::path::{self, Path, PathBuf};
use std::time::{Duration, SystemTime};

use chrono::prelude::*;
use chrono::Duration as CDuration;
use rusqlite::ToSql;
use rusqlite::{params, OptionalExtension, Transaction, NO_PARAMS};

#[cfg(target_family = "unix")]
use std::os::unix::fs::DirBuilderExt;

pub struct SqliteStore {
    conn: rusqlite::Connection,
    path: PathBuf,
}

impl SqliteStore {
    pub fn from_path<P>(path: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref();
        let sqlpath = path.join("dir.sqlite3");
        let blobpath = path.join("dir_blobs/");

        #[cfg(target_family = "unix")]
        {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&blobpath)?;
        }
        #[cfg(not(target_family = "unix"))]
        {
            std::fs::DirBuilder::new()
                .recursive(true)
                .create(&blobpath)?;
        }
        let conn = rusqlite::Connection::open(&sqlpath)?;
        SqliteStore::from_conn(conn, &blobpath)
    }

    pub fn from_conn<P>(conn: rusqlite::Connection, path: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref().to_path_buf();
        let mut result = SqliteStore { conn, path };

        result.check_schema()?;

        Ok(result)
    }

    fn check_schema(&mut self) -> Result<()> {
        let tx = self.conn.transaction()?;
        let db_n_tables: u32 = tx.query_row(
            "SELECT COUNT(name) FROM sqlite_master
             WHERE type='table'
             AND name NOT LIKE 'sqlite_%'",
            NO_PARAMS,
            |row| row.get(0),
        )?;
        let db_exists = db_n_tables > 0;

        if !db_exists {
            tx.execute_batch(INSTALL_SCHEMA)?;
            tx.commit()?;
            return Ok(());
        }

        let (version, readable_by): (u32, u32) = tx.query_row(
            "SELECT version, readable_by FROM TorSchemaMeta
             WHERE name = 'TorDirStorage'",
            NO_PARAMS,
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;

        /* if version < SCHEMA_VERSION {
            // Update the schema. XXXX
            tx.commit();
            return Ok(())
        } else */
        if readable_by > SCHEMA_VERSION {
            return Err(Error::UnrecognizedSchema.into());
        }

        // rolls back the transaction, but nothing was done.
        Ok(())
    }

    fn expire_all(&mut self) -> Result<()> {
        let tx = self.conn.transaction()?;
        let expired_blobs: Vec<String> = {
            let mut stmt = tx.prepare(FIND_EXPIRED_EXTDOCS)?;
            let names = stmt
                .query_map(NO_PARAMS, |row| row.get::<_, String>(0))?
                .filter_map(std::result::Result::ok)
                .collect();
            names
        };

        tx.execute(DROP_OLD_EXTDOCS, NO_PARAMS)?;
        tx.execute(DROP_OLD_MICRODESCS, NO_PARAMS)?;
        tx.execute(DROP_OLD_AUTHCERTS, NO_PARAMS)?;
        tx.execute(DROP_OLD_CONSENSUSES, NO_PARAMS)?;
        tx.commit();
        for name in expired_blobs {
            let fname = self.blob_fname(name);
            if let Ok(fname) = fname {
                let _ignore = std::fs::remove_file(fname);
            }
        }
        Ok(())
    }

    fn blob_fname<P>(&self, path: P) -> Result<PathBuf>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref();
        if !path
            .components()
            .all(|c| matches!(c, path::Component::Normal(_)))
        {
            return Err(Error::CacheCorruption("Invalid path in database").into());
        }

        let mut result = self.path.clone();
        result.push(path);
        Ok(result)
    }

    fn read_blob<P>(&self, path: P) -> Result<InputString>
    where
        P: AsRef<Path>,
    {
        let full_path = self.blob_fname(path)?;
        InputString::load(full_path)
    }

    fn save_blob_internal(
        &mut self,
        contents: &[u8],
        doctype: &str,
        dtype: &str,
        digest: &[u8],
        expires: DateTime<Utc>,
    ) -> Result<SavedBlobHandle<'_>> {
        let digest = hex::encode(digest);
        let digeststr = format!("{}-{}", dtype, digest);
        let fname = format!("{}:{}", doctype, digeststr);
        let full_path = self.blob_fname(&fname)?;

        let unlinker = Unlinker::new(&full_path);
        std::fs::write(full_path, contents)?;

        let tx = self.conn.unchecked_transaction()?;
        tx.execute(INSERT_EXTDOC, params![digeststr, expires, dtype, fname]);

        Ok(SavedBlobHandle {
            tx,
            digeststr,
            fname,
            unlinker,
        })
    }

    #[cfg(test)]
    fn save_blob(
        &mut self,
        contents: &[u8],
        doctype: &str,
        dtype: &str,
        digest: &[u8],
        expires: DateTime<Utc>,
    ) -> Result<String> {
        let h = self.save_blob_internal(contents, doctype, dtype, digest, expires)?;
        let SavedBlobHandle {
            tx,
            digeststr,
            fname,
            unlinker,
        } = h;
        tx.commit()?;
        unlinker.forget();
        Ok(fname)
    }

    pub fn store_consensus(
        &mut self,
        cmeta: &ConsensusMeta,
        pending: bool,
        contents: &str,
    ) -> Result<()> {
        let lifetime = cmeta.lifetime();
        let sha3_256_digest = cmeta.sha3_256_of_signed();
        let valid_after: DateTime<Utc> = lifetime.valid_after().into();
        let fresh_until: DateTime<Utc> = lifetime.fresh_until().into();
        let valid_until: DateTime<Utc> = lifetime.valid_after().into();

        // After a few days have passed, a consensus is no good for
        // anything at all, not even diffs.
        let expires = valid_until + CDuration::days(4);

        // We should probably use a different digest for indexing, since
        // this sha3_256_digest doesn't cover the whole document. XXXX

        let h = self.save_blob_internal(
            contents.as_bytes(),
            "mdcon",
            "sha3-256",
            &sha3_256_digest[..],
            expires,
        )?;
        h.tx.execute(
            INSERT_CONSENSUS,
            params![
                valid_after,
                fresh_until,
                valid_until,
                "microdesc",
                pending,
                h.digeststr
            ],
        )?;
        h.tx.commit()?;
        h.unlinker.forget();
        Ok(())
    }

    pub fn latest_consensus_time(&self) -> Result<Option<DateTime<Utc>>> {
        if let Some(va) = self
            .conn
            .query_row(FIND_LATEST_CONSENSUS_TIME, NO_PARAMS, |row| row.get(0))
            .optional()?
        {
            Ok(Some(va))
        } else {
            Ok(None)
        }
    }

    pub fn latest_consensus(&self, pending: bool) -> Result<Option<InputString>> {
        let rv: Option<(DateTime<Utc>, DateTime<Utc>, String)> = self
            .conn
            .query_row(FIND_CONSENSUS, params![pending], |row| row.try_into())
            .optional()?;

        if let Some((va, vu, filename)) = rv {
            let full_path = self.blob_fname(filename)?;
            Ok(Some(InputString::load(full_path)?))
        } else {
            Ok(None)
        }
    }

    pub fn store_authcerts(&mut self, certs: &[(AuthCert, &str)]) -> Result<()> {
        let tx = self.conn.transaction()?;
        let mut stmt = tx.prepare(INSERT_AUTHCERT)?;
        for (cert, content) in certs {
            let id_digest = hex::encode(cert.id_fingerprint().as_bytes());
            let sk_digest = hex::encode(cert.sk_fingerprint().as_bytes());
            let published: DateTime<Utc> = cert.published().into();
            let expires: DateTime<Utc> = cert.expires().into();
            stmt.execute(params![id_digest, sk_digest, published, expires, content])?;
        }
        stmt.finalize()?;
        tx.commit()?;
        Ok(())
    }

    pub fn authcerts(&self, certs: &[AuthCertKeyIds]) -> Result<HashMap<AuthCertKeyIds, String>> {
        let mut result = HashMap::new();
        // XXXX Do I need to get a transaction here for performance?
        let mut stmt = self.conn.prepare(FIND_AUTHCERT)?;

        for ids in certs {
            let id_digest = hex::encode(ids.id_fingerprint.as_bytes());
            let sk_digest = hex::encode(ids.sk_fingerprint.as_bytes());
            if let Some(contents) = stmt
                .query_row(params![id_digest, sk_digest], |row| row.get::<_, String>(0))
                .optional()?
            {
                result.insert((*ids).clone(), contents);
            }
        }

        Ok(result)
    }

    pub fn microdescs<'a, I>(&self, input: I) -> Result<HashMap<MDDigest, String>>
    where
        I: IntoIterator<Item = &'a MDDigest>,
    {
        let mut result = HashMap::new();
        let mut stmt = self.conn.prepare(FIND_MD)?;

        // XXXX Should I speed this up with a transaction, or does it not
        // matter for queries?
        for md_digest in input.into_iter() {
            let h_digest = hex::encode(md_digest);
            if let Some(contents) = stmt
                .query_row(params![h_digest], |row| row.get::<_, String>(0))
                .optional()?
            {
                result.insert(*md_digest, contents);
            }
        }

        Ok(result)
    }

    pub fn update_microdescs_listed<'a, I>(&mut self, input: I, when: SystemTime) -> Result<()>
    where
        I: IntoIterator<Item = &'a MDDigest>,
    {
        let mut tx = self.conn.transaction()?;
        let mut stmt = tx.prepare(UPDATE_MD_LISTED)?;
        let when: DateTime<Utc> = when.into();

        for md_digest in input.into_iter() {
            let h_digest = hex::encode(md_digest);
            stmt.execute(params![when, h_digest])?;
        }

        stmt.finalize()?;
        tx.commit()?;
        Ok(())
    }

    pub fn store_microdescs<'a, I>(&mut self, input: I, when: SystemTime) -> Result<()>
    where
        I: IntoIterator<Item = (&'a str, &'a Microdesc)>,
    {
        let when: DateTime<Utc> = when.into();

        let mut tx = self.conn.transaction()?;
        let mut stmt = tx.prepare(INSERT_MD)?;

        for (content, md) in input.into_iter() {
            let h_digest = hex::encode(md.digest());
            stmt.execute(params![h_digest, when, content])?;
        }
        stmt.finalize()?;
        tx.commit()?;
        Ok(())
    }
}

struct SavedBlobHandle<'a> {
    tx: Transaction<'a>,
    digeststr: String,
    fname: String,
    unlinker: Unlinker,
}

struct Unlinker {
    p: Option<PathBuf>,
}
impl Unlinker {
    fn new<P: AsRef<Path>>(p: P) -> Self {
        Unlinker {
            p: Some(p.as_ref().to_path_buf()),
        }
    }
    fn forget(mut self) {
        self.p = None
    }
}
impl Drop for Unlinker {
    fn drop(&mut self) {
        if let Some(p) = self.p.take() {
            let _ignore_err = std::fs::remove_file(p);
        }
    }
}

/*
impl ReadableStore for SqliteStore {


}
 */

fn sys_to_naive(t: SystemTime) -> NaiveDateTime {
    let t: DateTime<Utc> = t.into();
    t.naive_utc()
}
fn naive_to_sys(t: NaiveDateTime) -> SystemTime {
    let t = DateTime::<Utc>::from_utc(t, Utc);
    t.into()
}

const SCHEMA_VERSION: u32 = 0;

const INSTALL_SCHEMA: &str = "
  CREATE TABLE TorSchemaMeta (
     name TEXT NOT NULL PRIMARY KEY,
     version INTEGER NOT NULL,
     readable_by INTEGER NOT NULL
  );

  INSERT INTO TorSchemaMeta (name, version, readable_by) VALUES ( 'TorDirStorage', 0, 0 );

  CREATE TABLE ExtDocs (
    digest TEXT PRIMARY KEY NOT NULL,
    created DATE NOT NULL,
    expires DATE NOT NULL,
    type TEXT NOT NULL,
    filename TEXT NOT NULL
  );

  CREATE TABLE Microdescs (
    sha256_digest TEXT PRIMARY KEY NOT NULL,
    last_listed DATE NOT NULL,
    contents BLOB NOT NULL
  );

  CREATE TABLE Authcerts (
    id_digest TEXT NOT NULL,
    sk_digest TEXT NOT NULL,
    published DATE NOT NULL,
    expires DATE NOT NULL,
    contents BLOB NOT NULL,
    PRIMARY KEY (id_digest, sk_digest)
  );

  CREATE TABLE Consensuses (
    valid_after DATE NOT NULL,
    fresh_until DATE NOT NULL,
    valid_until DATE NOT NULL,
    flavor TEXT NOT NULL,
    pending BOOLEAN NOT NULL,
    digest TEXT NOT NULL,
    FOREIGN KEY (digest) REFERENCES ExtDocs (digest) ON DELETE CASCADE
  );
  CREATE INDEX Consensuses_vu on CONSENSUSES(valid_until);

";

const FIND_CONSENSUS: &str = "
  SELECT valid_after, valid_until, filename
  FROM Consensuses
  INNER JOIN ExtDocs ON ExtDocs.digest = Consensuses.digest
  WHERE pending = ? AND flavor = 'microdesc'
  ORDER BY valid_until DESC
  LIMIT 1;
";

const FIND_LATEST_CONSENSUS_TIME: &str = "
  SELECT valid_after
  FROM Consensuses
  WHERE pending = 0 AND flavor = 'microdesc'
  ORDER BY valid_until DESC
  LIMIT 1;
";

const FIND_AUTHCERT: &str = "
  SELECT contents FROM AuthCerts WHERE id_digest = ? AND sk_digest = ?;
";
const FIND_MD: &str = "
  SELECT contents
  FROM Microdescs
  WHERE sha256_digest = ?
";
const FIND_EXPIRED_EXTDOCS: &str = "
  SELECT filename FROM Extdocs where expires < datetime('now');
";

const INSERT_EXTDOC: &str = "
  INSERT INTO ExtDocs ( digest, created, expires, type, filename )
  VALUES ( ?, datetime('now'), ?, ?, ? );
";
const INSERT_CONSENSUS: &str = "
  INSERT INTO Consensuses
    ( valid_after, fresh_until, valid_until, flavor, pending, digest )
  VALUES ( ?, ?, ?, ?, ?, ? );
";
const INSERT_AUTHCERT: &str = "
  INSERT INTO Authcerts
    ( id_digest, sk_digest, published, expires, contents)
  VALUES ( ?, ?, ?, ?, ? );
";
const INSERT_MD: &str = "
  INSERT INTO Microdescs ( sha256_digest, last_listed, contents )
  VALUES ( ?, ?, ? );
";

const UPDATE_MD_LISTED: &str = "
  UPDATE Microdescs
  SET last_listed = ?
  WHERE sha256_digest = ?;
";

const DROP_OLD_EXTDOCS: &str = "
  DELETE FROM ExtDocs WHERE expires < datetime('now');
";
const DROP_OLD_MICRODESCS: &str = "
  DELETE FROM Microdescs WHERE last_listed < datetime('now','-3 months');
";
const DROP_OLD_AUTHCERTS: &str = "
  DELETE FROM Authcerts WHERE expires < datetime('now');
";
const DROP_OLD_CONSENSUSES: &str = "
  DELETE FROM Consensuses WHERE valid_until < datetime('now','-2 days');
";

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;
    use tempdir::TempDir;

    fn new_empty() -> Result<(TempDir, SqliteStore)> {
        let tmp_dir = TempDir::new("arti-nd").unwrap();
        let sql_path = tmp_dir.path().join("db.sql");
        let conn = rusqlite::Connection::open(&sql_path)?;
        let store = SqliteStore::from_conn(conn, &tmp_dir)?;

        Ok((tmp_dir, store))
    }

    #[test]
    fn init() -> Result<()> {
        let tmp_dir = TempDir::new("arti-nd").unwrap();
        let sql_path = tmp_dir.path().join("db.sql");
        // Initial setup: everything should work.
        {
            let conn = rusqlite::Connection::open(&sql_path)?;
            let store = SqliteStore::from_conn(conn, &tmp_dir)?;
        }
        // Second setup: shouldn't need to upgrade.
        {
            let conn = rusqlite::Connection::open(&sql_path)?;
            let store = SqliteStore::from_conn(conn, &tmp_dir)?;
        }
        // Third setup: shouldn't need to upgrade.
        {
            let conn = rusqlite::Connection::open(&sql_path)?;
            conn.execute_batch("UPDATE TorSchemaMeta SET version = 9002;")?;
            let store = SqliteStore::from_conn(conn, &tmp_dir)?;
        }
        // Fourth: this says we can't read it, so we'll get an error.
        {
            let conn = rusqlite::Connection::open(&sql_path)?;
            conn.execute_batch("UPDATE TorSchemaMeta SET readable_by = 9001;")?;
            let val = SqliteStore::from_conn(conn, &tmp_dir);
            assert!(val.is_err());
        }
        Ok(())
    }

    #[test]
    fn blobs() -> Result<()> {
        let (tmp_dir, mut store) = new_empty()?;

        let now = Utc::now();
        let one_week = CDuration::weeks(1);

        let fname1 = store.save_blob(
            b"Hello world",
            "greeting",
            "sha1",
            &hex!("7b502c3a1f48c8609ae212cdfb639dee39673f5e"),
            now + one_week,
        )?;

        let fname2 = store.save_blob(
            b"Goodbye, dear friends",
            "greeting",
            "sha1",
            &hex!("2149c2a7dbf5be2bb36fb3c5080d0fb14cb3355c"),
            now - one_week,
        )?;

        assert_eq!(
            fname1,
            "greeting:sha1-7b502c3a1f48c8609ae212cdfb639dee39673f5e"
        );
        assert_eq!(store.blob_fname(&fname1)?, tmp_dir.path().join(&fname1));
        assert_eq!(
            &std::fs::read(store.blob_fname(&fname1)?)?[..],
            b"Hello world"
        );
        assert_eq!(
            &std::fs::read(store.blob_fname(&fname2)?)?[..],
            b"Goodbye, dear friends"
        );

        let n: u32 =
            store
                .conn
                .query_row("SELECT COUNT(filename) FROM ExtDocs", NO_PARAMS, |row| {
                    row.get(0)
                })?;
        assert_eq!(n, 2);

        let blob = store.read_blob(&fname2)?;
        assert_eq!(blob.as_str().unwrap(), "Goodbye, dear friends");

        // Now expire: the second file should go away.
        store.expire_all()?;
        assert_eq!(
            &std::fs::read(store.blob_fname(&fname1)?)?[..],
            b"Hello world"
        );
        assert!(std::fs::read(store.blob_fname(&fname2)?).is_err());
        let n: u32 =
            store
                .conn
                .query_row("SELECT COUNT(filename) FROM ExtDocs", NO_PARAMS, |row| {
                    row.get(0)
                })?;
        assert_eq!(n, 1);

        Ok(())
    }

    #[test]
    fn consensus() -> Result<()> {
        let (tmp_dir, mut store) = new_empty()?;
        let now = Utc::now();
        let one_hour = CDuration::hours(1);

        let cmeta = ConsensusMeta::new(
            netstatus::Lifetime::new(
                now.into(),
                (now + one_hour).into(),
                (now + one_hour * 2).into(),
            ),
            [0xAB; 32],
        );

        store.store_consensus(&cmeta, false, "Pretend this is a consensus")?;

        let consensus = store.latest_consensus(false)?.unwrap();
        assert_eq!(consensus.as_str()?, "Pretend this is a consensus");

        Ok(())
    }
}
