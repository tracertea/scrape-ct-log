//! Thread that deals with outputting the data that is scraped.
//!
use ct_structs::v1::{
	response::GetSth as GetSthResponse, ExtraData, SignedEntry, TreeLeafEntry,
};
use serde::Serialize;

use gen_server::{GenServer, Status::Continue};
use url::Url;

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::marker::PhantomData;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{processor, Error};

pub use self::streaming_serializer::StreamFormat as OutputFormat;
use self::streaming_serializer::{StreamingMap, StreamingSeq, StreamingSerializer};

#[allow(clippy::result_large_err)] // Oh shoosh
fn current_time() -> Result<u64, Error> {
	#[allow(clippy::expect_used)] // I'll take the risk
	Ok(SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map_err(|e| Error::system("we went back in time somehow", e))?
		.as_millis()
		.try_into()
		.expect("wow this code has excellent shelf life"))
}

#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Args {
	output: Option<PathBuf>,
	log_url: Url,
	split_by: Option<u64>,
	format: OutputFormat,
	include_chains: bool,
	include_precert_data: bool,
}

impl Args {
	#[must_use]
	pub fn new(output: Option<PathBuf>, log_url: Url, split_by: Option<u64>) -> Self {
		Args {
			output,
			log_url,
			split_by,
			format: OutputFormat::default(),
			include_chains: false,
			include_precert_data: false,
		}
	}

	#[must_use]
	pub fn format(mut self, format: OutputFormat) -> Self {
		self.format = format;
		self
	}

	#[must_use]
	pub fn include_chains(mut self, include_chains: bool) -> Self {
		self.include_chains = include_chains;
		self
	}

	#[must_use]
	pub fn include_precert_data(mut self, include_precert_data: bool) -> Self {
		self.include_precert_data = include_precert_data;
		self
	}
}

pub type StopReason = ();

mod b64_serde {
	use base64::{engine::general_purpose::STANDARD_NO_PAD as b64, Engine as _};
	use serde::{Deserialize, Deserializer, Serializer};

	pub(crate) fn serialize<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
		s.serialize_str(&b64.encode(b))
	}

	#[allow(dead_code)]
	pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
		let s: &str = Deserialize::deserialize(d)?;
		b64.decode(s).map_err(serde::de::Error::custom)
	}
}

#[derive(Serialize)]
struct JsonlPrecert<'a> {
	#[serde(with = "b64_serde")]
	issuer_key_hash: &'a [u8],
	#[serde(with = "b64_serde")]
	tbs_certificate: &'a [u8],
}

#[derive(Serialize)]
struct JsonlEntry<'a> {
	entry_number: u64,
	timestamp: u64,
	#[serde(with = "b64_serde")]
	certificate: &'a [u8],
	#[serde(skip_serializing_if = "Option::is_none")]
	chain: Option<Vec<Vec<u8>>>,
	#[serde(skip_serializing_if = "Option::is_none")]
	precertificate: Option<JsonlPrecert<'a>>,
}

#[derive(Serialize)]
struct Metadata<'a> {
	log_url: &'a Url,
	scrape_begin_timestamp: u64,
	scrape_end_timestamp: u64,
	sth: &'a GetSthResponse,
}

enum State<'a> {
	Jsonl {
		log_url: Url,
		sth: Option<GetSthResponse>,
		scrape_begin_timestamp: u64,
		metadata_path: Option<PathBuf>,
		output_path: Option<PathBuf>,
		split_by: Option<u64>,
		writers: HashMap<u64, BufWriter<Box<dyn Write + Send + Sync + 'a>>>,
		include_chains: bool,
		include_precert_data: bool,
	},
	Cbor {
		map: StreamingMap<'a>,
		entries: Option<StreamingSeq<'a>>,
		include_chains: bool,
		include_precert_data: bool,
	},
}

pub struct FileWriter<'a> {
	state: State<'a>,
	_m: PhantomData<&'a ()>,
}

impl std::fmt::Debug for FileWriter<'_> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
		f.debug_struct("FileWriter").finish()
	}
}

mod streaming_serializer;

impl<'a> GenServer for FileWriter<'a> {
	type Args = Args;
	type Error = Error;
	type Request = processor::Request;
	type StopReason = ();

	fn init(args: Args) -> Result<Self, Self::Error> {
		let state = match args.format {
			OutputFormat::JSONL => {
				let mut writers: HashMap<u64, BufWriter<Box<dyn Write + Send + Sync + 'a>>> =
					HashMap::new();
				let metadata_path: Option<PathBuf>;
				let output_path: Option<PathBuf>;

				if let Some(p) = args.output {
					let mut mp = p.as_os_str().to_owned();
					mp.push(".metadata.json");
					metadata_path = Some(PathBuf::from(mp));
					output_path = Some(p.clone());

					if args.split_by.is_none() {
						let file: Box<dyn Write + Send + Sync + 'a> = Box::new(
							File::create(&p)
								.map_err(|e| Error::system("failed to create output file", e))?,
						);
						writers.insert(0, BufWriter::new(file));
					}
				} else {
					let stdout: Box<dyn Write + Send + Sync + 'a> = Box::new(io::stdout());
					writers.insert(0, BufWriter::new(stdout));
					metadata_path = None;
					output_path = None;
				}

				State::Jsonl {
					log_url: args.log_url,
					scrape_begin_timestamp: current_time()?,
					sth: None,
					metadata_path,
					output_path,
					split_by: args.split_by,
					writers,
					include_chains: args.include_chains,
					include_precert_data: args.include_precert_data,
				}
			}
			OutputFormat::CBOR => {
				let writer: Box<dyn Write + Send + Sync> = if let Some(p) = args.output {
					Box::new(
						File::create(&p)
							.map_err(|e| Error::system("failed to create output file", e))?,
					)
				} else {
					Box::new(io::stdout())
				};

				let ser = StreamingSerializer::new(Box::new(BufWriter::new(writer)), args.format);
				let mut map = ser.map().map_err(|e| Error::output("map open", e))?;
				map.key("log_url")
					.map_err(|e| Error::output("log_url key", e))?;
				map.string(args.log_url.as_ref())
					.map_err(|e| Error::output("log_url", e))?;
				map.key("scrape_begin_timestamp")
					.map_err(|e| Error::output("scrape_begin_timestamp key", e))?;
				map.uint(current_time()?)
					.map_err(|e| Error::output("scrape_begin_timestamp", e))?;

				State::Cbor {
					map,
					entries: None,
					include_chains: args.include_chains,
					include_precert_data: args.include_precert_data,
				}
			}
		};

		Ok(Self {
			state,
			_m: PhantomData,
		})
	}

	#[allow(clippy::too_many_lines)] // TODO: refactor
	fn handle_cast(
		&mut self,
		request: Self::Request,
	) -> Result<gen_server::Status<Self>, Self::Error> {
		match &mut self.state {
			State::Jsonl {
				sth,
				output_path,
				split_by,
				writers,
				include_chains,
				include_precert_data,
				..
			} => match request {
				processor::Request::Metadata(s) => {
					*sth = Some(s);
					Ok(Continue)
				}
				processor::Request::Entry(id, entry) => {
					let chunk_key = if let Some(split_size) = split_by {
						(id / *split_size) * *split_size
					} else {
						0
					};

					if !writers.contains_key(&chunk_key) {
						let p = output_path.as_ref().ok_or_else(|| {
							Error::internal("split_by is set but output_path is not")
						})?;

						let stem = p
							.file_stem()
							.and_then(std::ffi::OsStr::to_str)
							.unwrap_or_default();
						let ext = p
							.extension()
							.and_then(std::ffi::OsStr::to_str)
							.unwrap_or("jsonl");

						let new_filename = format!("{stem}.{chunk_key}.{ext}");
						let new_path = p.with_file_name(new_filename);

						let file: Box<dyn Write + Send + Sync> = Box::new(
							File::create(new_path)
								.map_err(|e| Error::system("failed to create chunk file", e))?,
						);

						writers.insert(chunk_key, BufWriter::new(file));
					}

					let current_writer = writers
						.get_mut(&chunk_key)
						.ok_or_else(|| Error::internal("writer is not available for entry chunk"))?;

					let (timestamp, certificate, chain_certs, precert) =
						if let TreeLeafEntry::TimestampedEntry(ts_entry) = &entry.leaf_input.entry {
							match (&ts_entry.signed_entry, &entry.extra_data) {
								(
									SignedEntry::X509Entry(x509_entry),
									ExtraData::X509ExtraData(extra_data),
								) => Ok((
									ts_entry.timestamp,
									&x509_entry.certificate,
									&extra_data.certificate_chain,
									None,
								)),
								(
									SignedEntry::PrecertEntry(precert_entry),
									ExtraData::PrecertExtraData(extra_data),
								) => Ok((
									ts_entry.timestamp,
									&extra_data.pre_certificate.certificate,
									&extra_data.precertificate_chain,
									Some(precert_entry),
								)),
								_ => Err(Error::InternalError(format!(
									"incompatible combination of signed_entry and extra_data ({:?} vs {:?})",
									ts_entry.signed_entry, entry.extra_data
								))),
							}
						} else {
							Err(Error::EntryDecodingError(
								"leaf_input was not a TimestampedEntry".to_string(),
							))
						}?;

					let chain = if *include_chains {
						Some(
							chain_certs
								.iter()
								.map(|c| c.certificate.clone())
								.collect(),
						)
					} else {
						None
					};

					let precertificate = if *include_precert_data {
						precert.map(|p| JsonlPrecert {
							issuer_key_hash: &p.issuer_key_hash,
							tbs_certificate: &p.tbs_certificate,
						})
					} else {
						None
					};

					let jsonl_entry = JsonlEntry {
						entry_number: id,
						timestamp,
						certificate,
						chain,
						precertificate,
					};

					serde_json::to_writer(&mut *current_writer, &jsonl_entry)
						.map_err(|e| Error::output("jsonl entry", e))?;
					current_writer
						.write_all(b"\n")
						.map_err(|e| Error::output("jsonl newline", e))?;

					Ok(Continue)
				}
			},
			State::Cbor {
				map,
				entries,
				include_chains,
				include_precert_data,
			} => match request {
				processor::Request::Metadata(sth) => {
					map.key("sth").map_err(|e| Error::output("sth key", e))?;
					let mut sth_map = map.map().map_err(|e| Error::output("sth map open", e))?;
					sth_map
						.key("tree_size")
						.map_err(|e| Error::output("tree_size key", e))?;
					sth_map
						.uint(sth.tree_size)
						.map_err(|e| Error::output("tree_size", e))?;
					sth_map
						.key("timestamp")
						.map_err(|e| Error::output("timestamp key", e))?;
					sth_map
						.uint(sth.timestamp)
						.map_err(|e| Error::output("timestamp", e))?;
					sth_map
						.key("sha256_root_hash")
						.map_err(|e| Error::output("sha256_root_hash key", e))?;
					sth_map
						.bytes(&sth.sha256_root_hash)
						.map_err(|e| Error::output("sha256_root_hash", e))?;
					sth_map
						.key("tree_head_signature")
						.map_err(|e| Error::output("tree_head_signature key", e))?;
					sth_map
						.bytes(&sth.tree_head_signature)
						.map_err(|e| Error::output("tree_head_signature", e))?;
					sth_map
						.end()
						.map_err(|e| Error::output("sth map close", e))?;
					Ok(Continue)
				}
				processor::Request::Entry(id, entry) => {
					if entries.is_none() {
						map.key("entries")
							.map_err(|e| Error::output("entries key", e))?;
						let e = map.seq().map_err(|e| Error::output("entries open", e))?;
						*entries = Some(e);
					}

					if let Some(entries) = entries {
						let mut entry_map =
							entries.map().map_err(|e| Error::output("entry map open", e))?;

						let (timestamp, certificate, chain_certs, precert) =
							if let TreeLeafEntry::TimestampedEntry(ts_entry) =
								&entry.leaf_input.entry
							{
								match (&ts_entry.signed_entry, &entry.extra_data) {
									(
										SignedEntry::X509Entry(x509_entry),
										ExtraData::X509ExtraData(extra_data),
									) => Ok((
										ts_entry.timestamp,
										&x509_entry.certificate,
										&extra_data.certificate_chain,
										None,
									)),
									(
										SignedEntry::PrecertEntry(precert_entry),
										ExtraData::PrecertExtraData(extra_data),
									) => Ok((
										ts_entry.timestamp,
										&extra_data.pre_certificate.certificate,
										&extra_data.precertificate_chain,
										Some(precert_entry.clone()),
									)),
									_ => Err(Error::InternalError(format!(
										"incompatible combination of signed_entry and extra_data ({:?} vs {:?})",
										ts_entry.signed_entry, entry.extra_data
									))),
								}
							} else {
								Err(Error::EntryDecodingError(
									"leaf_input was not a TimestampedEntry".to_string(),
								))
							}?;

						entry_map
							.key("entry_number")
							.map_err(|e| Error::output("entry_number key", e))?;
						entry_map
							.uint(id)
							.map_err(|e| Error::output("entry_number", e))?;
						entry_map
							.key("timestamp")
							.map_err(|e| Error::output("timestamp key", e))?;
						entry_map
							.uint(timestamp)
							.map_err(|e| Error::output("timestamp", e))?;
						entry_map
							.key("certificate")
							.map_err(|e| Error::output("certificate key", e))?;
						entry_map
							.bytes(certificate)
							.map_err(|e| Error::output("certificate", e))?;

						if *include_chains {
							entry_map
								.key("chain")
								.map_err(|e| Error::output("chain key", e))?;
							let mut chain =
								entry_map.seq().map_err(|e| Error::output("chain open", e))?;

							for c in chain_certs {
								chain
									.bytes(&c.certificate)
									.map_err(|e| Error::output("chain entry", e))?;
							}

							chain.end().map_err(|e| Error::output("chain close", e))?;
						}

						if *include_precert_data {
							if let Some(precert) = precert {
								entry_map
									.key("precert")
									.map_err(|e| Error::output("precert key", e))?;
								let mut precert_map = entry_map
									.map()
									.map_err(|e| Error::output("precert open", e))?;

								precert_map
									.key("issuer_key_hash")
									.map_err(|e| Error::output("issuer_key_hash key", e))?;
								precert_map
									.bytes(&precert.issuer_key_hash)
									.map_err(|e| Error::output("issuer_key_hash", e))?;
								precert_map
									.key("tbs_certificate")
									.map_err(|e| Error::output("tbs_certificate key", e))?;
								precert_map
									.bytes(&precert.tbs_certificate)
									.map_err(|e| Error::output("tbs_certificate", e))?;

								precert_map
									.end()
									.map_err(|e| Error::output("precert close", e))?;
							}
						}

						entry_map
							.end()
							.map_err(|e| Error::output("entry map close", e))?;
					}

					Ok(Continue)
				}
			},
		}
	}

	fn terminate(&mut self, _reason: Result<(), Error>) {
		match &mut self.state {
			State::Jsonl {
				log_url,
				sth,
				scrape_begin_timestamp,
				metadata_path,
				writers,
				..
			} => {
				for (_, mut writer) in writers.drain() {
					drop(writer.flush());
				}

				if let (Some(path), Some(sth_val)) = (metadata_path, sth.as_ref()) {
					let metadata = Metadata {
						log_url,
						scrape_begin_timestamp: *scrape_begin_timestamp,
						scrape_end_timestamp: current_time().unwrap_or(0),
						sth: sth_val,
					};

					if let Ok(file) = File::create(path) {
						let mut writer = BufWriter::new(file);
						if let Ok(()) = serde_json::to_writer_pretty(&mut writer, &metadata) {
							drop(writer.write_all(b"\n"));
						}
						drop(writer.flush());
					}
				}
			}
			State::Cbor { map, entries, .. } => {
				if let Some(ref mut entries) = entries {
					drop(entries.end().map_err(|e| Error::output("entries close", e)));
				}
				if let Ok(time) = current_time() {
					drop(
						map.key("scrape_end_timestamp")
							.map_err(|e| Error::output("scrape_end_timestamp key", e)),
					);
					drop(
						map.uint(time)
							.map_err(|e| Error::output("scrape_end_timestamp", e)),
					);
				}
				drop(map.end().map_err(|e| Error::output("map close", e)));
			}
		}
	}
}