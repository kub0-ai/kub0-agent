use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

pub struct GeoDb {
    reader: Option<maxminddb::Reader<Vec<u8>>>,
    centroids: HashMap<String, (f64, f64)>,
    mmdb_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GeoHit {
    pub country: String,
    pub lat: f64,
    pub lon: f64,
}

/// Where a database may be: inside the data dir the daemon was given. (The
/// map's country database can also be named outright with `--mmdb`; nothing
/// that enforces a rule reads that one.)
///
/// There used to be a third place, `data/geoip/<name>` under the working
/// directory. The panel gives its own daemon a data dir and a bare `kub0d`
/// defaults to `data`, so that only ever mattered when the data dir had no
/// database. A system daemon's working directory is `/`: it would then read
/// `/data/geoip/…`, a path it does not own and another account may be able to
/// write, and build an org's country and network rules from it, with nothing
/// in its log to say where the database had come from.
fn db_candidates(data_dir: &Path, name: &str) -> [PathBuf; 2] {
    [data_dir.join("geoip").join(name), data_dir.join(name)]
}

impl GeoDb {
    pub fn load(data_dir: &Path, mmdb_override: Option<&Path>) -> Self {
        let centroids = load_centroids(data_dir);
        let candidates: Vec<PathBuf> = mmdb_override
            .map(|p| vec![p.to_path_buf()])
            .unwrap_or_else(|| db_candidates(data_dir, "dbip-country-lite.mmdb").to_vec());
        let mut reader = None;
        let mut mmdb_path = None;
        for p in candidates {
            if p.is_file() {
                match maxminddb::Reader::open_readfile(&p) {
                    Ok(r) => {
                        mmdb_path = Some(p);
                        reader = Some(r);
                        break;
                    }
                    Err(e) => eprintln!("kub0d: mmdb open failed for {}: {e}", p.display()),
                }
            }
        }
        Self {
            reader,
            centroids,
            mmdb_path,
        }
    }

    pub fn has_mmdb(&self) -> bool {
        self.reader.is_some()
    }

    pub fn mmdb_path(&self) -> Option<&Path> {
        self.mmdb_path.as_deref()
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<GeoHit> {
        if ip.is_loopback() || ip.is_unspecified() || is_private(ip) {
            return None;
        }
        let reader = self.reader.as_ref()?;
        // maxminddb 0.26+: lookup yields a LookupResult; decode() is Ok(None) when the
        // address has no record (0.25 signalled that with AddressNotFoundError).
        let country: maxminddb::geoip2::Country = reader.lookup(ip).ok()?.decode().ok().flatten()?;
        let iso = country.country.iso_code.or(country.registered_country.iso_code)?;
        let cc = iso.to_uppercase();
        let (lat, lon) = self.centroids.get(&cc).copied().unwrap_or((0.0, 0.0));
        Some(GeoHit {
            country: cc,
            lat,
            lon,
        })
    }

    pub fn centroid(&self, cc: &str) -> Option<(f64, f64)> {
        self.centroids.get(&cc.to_uppercase()).copied()
    }
}

/// Networks in a DB-IP / MaxMind tree whose record satisfies `keep`, as CIDR strings,
/// IPv4 then IPv6. IPv6 aliases of the IPv4 space (IPv4-compatible `::/96`, mapped
/// `::ffff:0:0/96`, 6to4 `2002::/16`) are skipped: they would repeat every IPv4 range.
fn networks_where<'de, T, F>(reader: &'de maxminddb::Reader<Vec<u8>>, keep: F) -> Vec<String>
where
    T: serde::Deserialize<'de> + 'de,
    F: Fn(&T) -> bool,
{
    let mut out = Vec::new();
    for root in ["0.0.0.0/0", "::/0"] {
        let Ok(net) = root.parse::<ipnetwork::IpNetwork>() else { continue };
        let Ok(iter) = reader.within(net, maxminddb::WithinOptions::default()) else { continue };
        for item in iter.flatten() {
            let Ok(ip_net) = item.network() else { continue };
            if let ipnetwork::IpNetwork::V6(v6) = ip_net {
                let seg = v6.network().segments();
                let v4_alias = seg[..5] == [0; 5] && (seg[5] == 0 || seg[5] == 0xffff);
                if v4_alias || seg[0] == 0x2002 {
                    continue;
                }
            }
            let Ok(Some(info)) = item.decode::<T>() else { continue };
            if keep(&info) {
                out.push(format!("{}/{}", ip_net.network(), ip_net.prefix()));
            }
        }
    }
    out
}

impl GeoDb {
    /// Whether the database places any network in a country. False with no file, and
    /// for an mmdb of another kind at this path: an ASN database opens fine and gives
    /// every country no ranges. Stops at the first network that has one.
    pub fn has_country_data(&self) -> bool {
        let Some(reader) = self.reader.as_ref() else { return false };
        ["0.0.0.0/0", "::/0"].iter().any(|root| {
            let Ok(net) = root.parse::<ipnetwork::IpNetwork>() else { return false };
            let Ok(mut iter) = reader.within(net, maxminddb::WithinOptions::default()) else { return false };
            iter.any(|item| {
                item.ok()
                    .and_then(|r| r.decode::<maxminddb::geoip2::Country>().ok().flatten())
                    .is_some_and(|c| c.country.iso_code.is_some() || c.registered_country.iso_code.is_some())
            })
        })
    }

    /// Every network whose country is in `countries` (ISO alpha-2, upper case).
    pub fn networks_of_countries(&self, countries: &std::collections::BTreeSet<String>) -> Vec<String> {
        let Some(reader) = self.reader.as_ref() else { return Vec::new() };
        networks_where(reader, |c: &maxminddb::geoip2::Country| {
            c.country
                .iso_code
                .or(c.registered_country.iso_code)
                .is_some_and(|iso| countries.contains(&iso.to_ascii_uppercase()))
        })
    }
}

/// DB-IP ASN Lite (GeoLite2-ASN compatible). Optional: without it nothing is treated
/// as shared infrastructure, and the panel says so.
pub struct AsnDb {
    reader: Option<maxminddb::Reader<Vec<u8>>>,
}

impl AsnDb {
    pub fn load(data_dir: &Path) -> Self {
        for p in db_candidates(data_dir, "dbip-asn-lite.mmdb") {
            if p.is_file() {
                match maxminddb::Reader::open_readfile(&p) {
                    Ok(r) => return Self { reader: Some(r) },
                    Err(e) => eprintln!("kub0d: asn mmdb open failed for {}: {e}", p.display()),
                }
            }
        }
        Self::empty()
    }

    pub fn empty() -> Self {
        Self { reader: None }
    }

    pub fn has_mmdb(&self) -> bool {
        self.reader.is_some()
    }

    pub fn asn(&self, ip: IpAddr) -> Option<u32> {
        self.lookup(ip).map(|(asn, _)| asn)
    }

    /// Number and organisation name. The organisation is DB-IP's label for
    /// the network's registrant ("Hetzner Online GmbH"), which says who
    /// announces the range and nothing about who rents a machine in it.
    pub fn lookup(&self, ip: IpAddr) -> Option<(u32, Option<String>)> {
        let r = self.reader.as_ref()?;
        let hit: maxminddb::geoip2::Asn = r.lookup(ip).ok()?.decode().ok().flatten()?;
        let asn = hit.autonomous_system_number?;
        let org = hit
            .autonomous_system_organization
            .map(str::trim)
            .filter(|o| !o.is_empty())
            .map(str::to_string);
        Some((asn, org))
    }

    /// Every network announced by one of `asns`.
    pub fn networks_of(&self, asns: &[u32]) -> Vec<String> {
        let Some(reader) = self.reader.as_ref() else { return Vec::new() };
        networks_where(reader, |a: &maxminddb::geoip2::Asn| {
            a.autonomous_system_number.is_some_and(|n| asns.contains(&n))
        })
    }
}

fn load_centroids(data_dir: &Path) -> HashMap<String, (f64, f64)> {
    let mut map = HashMap::new();
    let bundled = include_str!("../../data/country-centroids.json");
    ingest_centroids(&mut map, bundled);
    let on_disk = data_dir.join("country-centroids.json");
    if let Ok(text) = std::fs::read_to_string(on_disk) {
        ingest_centroids(&mut map, &text);
    }
    map
}

fn ingest_centroids(map: &mut HashMap<String, (f64, f64)>, text: &str) {
    let parsed: HashMap<String, Vec<f64>> = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return,
    };
    for (k, v) in parsed {
        if v.len() >= 2 {
            map.insert(k.to_uppercase(), (v[0], v[1]));
        }
    }
}

pub fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_private() || v.is_link_local() || v.is_multicast() || v.is_broadcast(),
        IpAddr::V6(v) => {
            v.is_multicast()
                || v.is_unique_local()
                || v.is_unicast_link_local()
                || (v.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn data() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../data")
    }

    /// Every loader asks this where to look, the enforcer's included. Nothing
    /// it answers is outside the data dir, or relative to wherever the daemon
    /// happens to have been started.
    #[test]
    fn a_database_is_only_looked_for_inside_the_data_dir() {
        let dir = Path::new("/usr/share/kub0");
        for name in ["dbip-country-lite.mmdb", "dbip-asn-lite.mmdb"] {
            let places = db_candidates(dir, name);
            assert_eq!(places, [dir.join("geoip").join(name), dir.join(name)]);
            for p in &places {
                assert!(p.is_absolute() && p.starts_with(dir), "{}", p.display());
            }
        }
    }

    #[test]
    fn asn_lookup_and_enumeration_use_the_bundled_db() {
        let asn = AsnDb::load(&data());
        assert!(asn.has_mmdb(), "data/geoip/dbip-asn-lite.mmdb is bundled");
        assert_eq!(asn.asn("1.1.1.1".parse().unwrap()), Some(13335));
        let (n, org) = asn.lookup("1.1.1.1".parse().unwrap()).unwrap();
        assert_eq!(n, 13335);
        assert!(org.as_deref().is_some_and(|o| o.to_lowercase().contains("cloudflare")), "{org:?}");
        assert!(asn.lookup("127.0.0.1".parse().unwrap()).is_none());
        assert_eq!(asn.asn("198.51.100.7".parse().unwrap()), None);
        let cf = asn.networks_of(&[13335]);
        assert!(cf.iter().any(|n| n == "1.1.1.0/24" || n.starts_with("1.1.1.")), "Cloudflare v4 range missing");
        assert!(cf.iter().any(|n| n.starts_with("2606:4700")), "Cloudflare v6 range missing");
        assert!(!cf.iter().any(|n| n.starts_with("::ffff:") || n.starts_with("2002:")), "v4 alias leaked");
    }

    #[test]
    fn country_enumeration_matches_lookup() {
        let geo = GeoDb::load(&data(), None);
        let kp: std::collections::BTreeSet<String> = ["KP".to_string()].into();
        let nets = geo.networks_of_countries(&kp);
        // Leaf networks of the tree, not merged ranges: hundreds for a small country.
        assert!(!nets.is_empty() && nets.len() < 5_000, "KP ranges: {}", nets.len());
        for n in &nets {
            let ip: IpAddr = n.split('/').next().unwrap().parse().unwrap();
            assert_eq!(geo.lookup(ip).map(|h| h.country), Some("KP".into()), "{n}");
        }
    }

    #[test]
    fn only_a_country_database_has_country_data() {
        assert!(GeoDb::load(&data(), None).has_country_data());
        assert!(!GeoDb::load(Path::new("/nonexistent"), None).has_country_data());
        // The ASN database where the country one belongs: it opens, and knows no country.
        let wrong = GeoDb::load(Path::new("/nonexistent"), Some(&data().join("geoip/dbip-asn-lite.mmdb")));
        assert!(wrong.has_mmdb() && !wrong.has_country_data());
    }

    #[test]
    fn private_skipped() {
        let geo = GeoDb {
            reader: None,
            centroids: HashMap::new(),
            mmdb_path: None,
        };
        assert!(geo.lookup(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).is_none());
        assert!(geo.lookup(IpAddr::V4(Ipv4Addr::LOCALHOST)).is_none());
    }

    #[test]
    fn centroids_embedded() {
        let geo = GeoDb::load(Path::new("/nonexistent"), None);
        assert!(geo.centroid("US").is_some());
        assert!(geo.centroid("SE").is_some());
        let (lat, lon) = geo.centroid("JP").unwrap();
        assert!(lat > 30.0 && lat < 45.0);
        assert!(lon > 120.0 && lon < 150.0);
    }

    #[test]
    fn mmdb_google_dns() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../data");
        let geo = GeoDb::load(&root, None);
        if !geo.has_mmdb() {
            return;
        }
        let hit = geo
            .lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
            .expect("8.8.8.8 should resolve in DB-IP Country Lite");
        assert_eq!(hit.country.len(), 2);
        assert!(hit.lat != 0.0 || hit.lon != 0.0);
    }
}
