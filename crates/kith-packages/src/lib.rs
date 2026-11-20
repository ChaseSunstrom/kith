//! Packages (PLAN.md §4.8): a directory of resource templates with default values,
//! rendered for a release into resources.
//!
//! ```text
//! package.yaml          name, version, description, kithVersion, dependencies
//! values.yaml           the default values
//! values.schema.json    what values may be (optional)
//! templates/*.yaml      resources, as templates; `_name` files are only included
//! templates/*.kith      resources, in kith's own language; `_name` files are only imported
//! NOTES                 what to tell whoever installed it, a template too (optional)
//! ```
//!
//! Templates are Jinja (minijinja). They see `values`, `release.name`,
//! `release.namespace`, `package.name`, `package.version`, `name` (a name for the
//! release's resources) and `labels` (what every resource of the release is labelled
//! with); the filter `toYaml`, `required(value, "why")` and `lookup(kind, namespace, name)`
//! (the live resource's spec in the release's own namespace, an empty map when there is
//! none; a release is rendered again when what it looked up changes). A `.kith` file (kith-lang)
//! has the same names and is no template: it gives its resources itself.
//
// ponytail: `dependencies` are read and not rendered: that takes somewhere to get them
// from (Repository). The schema check knows the keywords in `KEYWORDS`, and says so
// about any other; the jsonschema crate if packages come to need more.

pub mod artifact;

use kith_api::Resource;
use kith_api::kinds::PackageRef;
use minijinja::{Environment, ErrorKind, UndefinedBehavior};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::Path;

type Fallible<T> = Result<T, String>;

/// How much work a package's templates may do: a loop without end stops here.
const FUEL: u64 = 500_000;
/// No template renders to more text than this, and no package has more files or more in them.
const TEXT_LIMIT: usize = 1 << 20;
/// The most resources one render gives, and the most text all its templates render to.
const RESOURCES_LIMIT: usize = 2000;
const RENDERED_LIMIT: usize = 4 << 20;
const FILES_LIMIT: usize = 200;
const PACKAGE_LIMIT: usize = 4 << 20;
/// No file of a package is bigger than this.
const FILE_LIMIT: u64 = 1 << 20;

const NOTES: &str = "NOTES";

pub const LABEL_RELEASE: &str = "kith.dev/release";
pub const LABEL_PACKAGE: &str = "kith.dev/package";

/// `package.yaml`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Meta {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: Option<String>,
    /// Semver range of kith versions the package supports.
    #[serde(default)]
    pub kith_version: Option<String>,
    #[serde(default)]
    pub dependencies: Vec<PackageRef>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Package {
    pub meta: Meta,
    /// `values.yaml`: an object.
    pub defaults: Value,
    pub schema: Option<Value>,
    /// Every file under `templates/`, by its path from the package (`templates/web.yaml`).
    pub templates: BTreeMap<String, String>,
    pub notes: Option<String>,
    /// Every file it was made from, as it was.
    pub files: BTreeMap<String, String>,
}

/// What a package is rendered for.
#[derive(Debug, Clone, Copy)]
pub struct Release<'a> {
    pub name: &'a str,
    pub namespace: &'a str,
}

#[derive(Debug, PartialEq)]
pub struct Rendered {
    pub resources: Vec<Resource>,
    pub notes: Option<String>,
    /// The keys `lookup` was asked for (found or not): what the render depends on besides its inputs.
    pub looked: std::collections::BTreeSet<String>,
}

/// The keys `lookup` was asked for, as it fills them in.
type Looked = std::sync::Arc<std::sync::Mutex<std::collections::BTreeSet<String>>>;

/// What `lookup(kind, namespace, name)` sees: the specs of the live resources of the
/// release's namespace, by key (`Kind/namespace/name`). The caller gives it (a render
/// has no store), and says in `refused` why it could not, when it could not.
#[cfg(feature = "live")]
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, Deserialize)]
pub struct Live {
    pub specs: BTreeMap<String, Value>,
    pub refused: Option<String>,
}

/// Put `over` on top of `base`: objects are merged key by key, anything else replaces.
pub fn merge(base: &mut Value, over: &Value) {
    match (base, over) {
        (Value::Object(base), Value::Object(over)) => {
            for (key, value) in over {
                merge(base.entry(key).or_insert(Value::Null), value);
            }
        }
        (base, over) => *base = over.clone(),
    }
}

pub use kith_api::schema::{check, unknown_keywords};

/// A name for the release's resources: the release's own if it says what the package
/// is, else both; no longer than a name may be.
fn full_name(release: &str, package: &str) -> String {
    let mut name = match release.contains(package) {
        true => release.to_string(),
        false => format!("{release}-{package}"),
    };
    name.truncate(63);
    name.trim_end_matches(['-', '.']).to_string()
}

/// Is `name` one a resource could have? (What templates write it into is YAML: a name
/// with anything else in it could say more than a name.)
fn named(what: &str, name: &str) -> Fallible<()> {
    let fine = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.';
    let ends = |c: char| c.is_ascii_alphanumeric();
    let sized = !name.is_empty() && name.len() <= 63;
    match sized && name.bytes().all(fine) && name.starts_with(ends) && name.ends_with(ends) {
        true => Ok(()),
        false => Err(format!(
            "{what} `{name}`: use lowercase letters, digits, `-` and `.`, starting and ending with a letter or digit, at most 63 characters"
        )),
    }
}

fn template_error(error: &minijinja::Error) -> String {
    // (The first cause is where it went wrong, when one template included another.)
    let mut said = error.to_string();
    let mut cause = std::error::Error::source(error);
    while let Some(inner) = cause {
        said = format!("{said}: {inner}");
        cause = inner.source();
    }
    said
}

impl Meta {
    /// Why the kith `running` is not one this package supports (its `kithVersion`, a
    /// semver range), or None when it is, or when the package asks for none. A
    /// pre-release kith counts as its release: `>=1.2` holds for `1.2.0-rc1`.
    pub fn kith_mismatch(&self, running: &str) -> Option<String> {
        let asked = self.kith_version.as_deref()?;
        let mut running_version = semver::Version::parse(running).ok()?;
        running_version.pre = semver::Prerelease::EMPTY;
        let said = |why: &str| format!("{} {} {why}, and this kith is {running}", self.name, self.version);
        match semver::VersionReq::parse(asked) {
            Ok(range) if range.matches(&running_version) => None,
            Ok(_) => Some(said(&format!("needs kith {asked}"))),
            Err(_) => Some(said(&format!("has a kithVersion `{asked}` that is no version range"))),
        }
    }
}

impl Package {
    /// A package from its files, by path from its directory.
    pub fn from_files(mut files: BTreeMap<String, String>) -> Fallible<Package> {
        artifact::plain(&files)?;
        let all = files.clone();
        let meta = files.remove("package.yaml").ok_or("no package.yaml")?;
        let meta: Meta = kith_yaml::from_str(&meta).map_err(|e| e.render("package.yaml", &meta))?;
        let defaults = match files.remove("values.yaml") {
            // (A file of comments only is no values, not a mistake.)
            Some(source) if kith_yaml::parse(&source).is_ok_and(|documents| documents.is_empty()) => json!({}),
            Some(source) => kith_yaml::from_str(&source).map_err(|e| e.render("values.yaml", &source))?,
            None => json!({}),
        };
        if !defaults.is_object() {
            return Err("values.yaml: the values must be a mapping".into());
        }
        let schema = files.remove("values.schema.json");
        let schema = schema.map(|schema| serde_json::from_str(&schema).map_err(|e| format!("values.schema.json: {e}")));
        Ok(Package {
            meta,
            defaults,
            schema: schema.transpose()?,
            notes: files.remove(NOTES),
            files: all,
            templates: files
                .into_iter()
                .filter(|(path, _)| path.starts_with("templates/"))
                .collect(),
        })
    }

    /// The package in the directory `dir`.
    pub fn load(dir: &Path) -> Fallible<Package> {
        let mut files = BTreeMap::new();
        let mut read = |path: &Path, name: String| -> Fallible<()> {
            let failed = |e: std::io::Error| format!("{}: {e}", path.display());
            if std::fs::metadata(path).map_err(failed)?.len() > FILE_LIMIT {
                return Err(format!("{}: bigger than {FILE_LIMIT} bytes", path.display()));
            }
            files.insert(name, std::fs::read_to_string(path).map_err(failed)?);
            Ok(())
        };
        // (A file itself, not a link to one: a package does not get to read what is
        // elsewhere on the machine of whoever renders it.)
        let is_file = |path: &Path| std::fs::symlink_metadata(path).is_ok_and(|file| file.is_file());
        for name in ["package.yaml", "values.yaml", "values.schema.json", NOTES] {
            if is_file(&dir.join(name)) {
                read(&dir.join(name), name.to_string())?;
            }
        }
        // (One level: a template is told by its file's name.)
        let templates = dir.join("templates");
        if templates.is_dir() {
            let failed = |e: std::io::Error| format!("{}: {e}", templates.display());
            for entry in std::fs::read_dir(&templates).map_err(failed)? {
                let entry = entry.map_err(failed)?;
                let name = entry.file_name().to_string_lossy().into_owned();
                if is_file(&entry.path()) {
                    read(&entry.path(), format!("templates/{name}"))?;
                }
            }
        }
        Package::from_files(files).map_err(|e| format!("{}: {e}", dir.display()))
    }

    /// The package as a `Package` resource, to keep in a cluster: `<name>-<version>`.
    pub fn resource(&self) -> Fallible<Resource> {
        let resource = json!({
            "apiVersion": "kith.dev/v1", "kind": "Package",
            "metadata": { "name": format!("{}-{}", self.meta.name, self.meta.version) },
            "spec": { "version": self.meta.version, "files": self.files },
        });
        let resource: Resource = serde_json::from_value(resource).map_err(|e| e.to_string())?;
        resource.validated()
    }

    /// The default values with each of `layers` on top, in turn; checked against the
    /// schema if the package has one.
    pub fn values(&self, layers: &[Value]) -> Fallible<Value> {
        let mut values = self.defaults.clone();
        for layer in layers {
            merge(&mut values, layer);
        }
        let mut wrong = Vec::new();
        if let Some(schema) = &self.schema {
            check(schema, &values, "values", &mut wrong);
        }
        match wrong.is_empty() {
            true => Ok(values),
            false => Err(wrong.join("\n")),
        }
    }

    fn environment(&self) -> Fallible<Environment<'_>> {
        let mut environment = Environment::new();
        environment.set_undefined_behavior(UndefinedBehavior::Strict);
        environment.set_fuel(Some(FUEL));
        // (With `namespace()` a loop can nest a value in itself as deep as it has fuel,
        // deeper than there is stack to write the value out, or even to let go of it.)
        environment.remove_global("namespace");
        // (And `debug()` writes out the whole context, at no cost in fuel.)
        environment.remove_global("debug");
        // What a template writes is put down as it is (`name: {{ name }}-page`); a value
        // that could be anything is quoted where it is used: `{{ values.page | tojson }}`.
        environment.set_auto_escape_callback(|_| minijinja::AutoEscape::None);
        environment.add_filter(
            "toYaml",
            |value: minijinja::Value| -> Result<String, minijinja::Error> {
                let value = serde_json::to_value(&value);
                let value = value.map_err(|e| minijinja::Error::new(ErrorKind::InvalidOperation, e.to_string()))?;
                Ok(kith_yaml::to_string(&value).trim_end().to_string())
            },
        );
        let required = |value: minijinja::Value, why: String| match value.is_undefined() || value.is_none() {
            true => Err(minijinja::Error::new(ErrorKind::MissingArgument, why)),
            false => Ok(value),
        };
        environment.add_function("required", required);
        environment.add_filter("required", required);
        let notes = self.notes.iter().map(|notes| (NOTES, notes));
        for (path, source) in self
            .templates
            .iter()
            .filter(|(path, _)| !path.ends_with(".kith"))
            .map(|(path, source)| (path.as_str(), source))
            .chain(notes)
        {
            let added = environment.add_template(path, source);
            added.map_err(|e| template_error(&e))?;
        }
        Ok(environment)
    }

    /// The package's resources for `release`, with `layers` of values over the defaults.
    /// Each resource is labelled as the release's, and is in the release's namespace
    /// unless its template says another. `lookup` finds nothing here (an empty list): no
    /// store to look in; `render_live` is the one that looks.
    pub fn render(&self, release: Release<'_>, layers: &[Value]) -> Fallible<Rendered> {
        self.render_with(release, layers, |environment| {
            let nothing = |_: minijinja::value::Rest<minijinja::Value>| Vec::<minijinja::Value>::new();
            environment.add_function("lookup", nothing);
            Looked::default()
        })
    }

    /// [`render`](Self::render) where `lookup` sees `live`. (A feature only kithd takes: the
    /// `kith` that renders by hand has no store, and its size is held.)
    #[cfg(feature = "live")]
    pub fn render_live(&self, release: Release<'_>, layers: &[Value], live: &Live) -> Fallible<Rendered> {
        self.render_with(release, layers, |environment| {
            let looked = Looked::default();
            let (seen, live, home) = (looked.clone(), live.clone(), release.namespace.to_string());
            // `lookup(kind, namespace, name)`: the live resource's spec, an empty map when there
            // is none. Only the release's own namespace is seen.
            environment.add_function("lookup", move |kind: String, namespace: String, name: String| {
                let wrong = |why: String| minijinja::Error::new(ErrorKind::InvalidOperation, why);
                if let Some(why) = &live.refused {
                    return Err(wrong(format!("lookup: {why}")));
                }
                if namespace != home {
                    let said = format!("lookup: a release sees only its own namespace ({home}), not `{namespace}`");
                    return Err(wrong(said));
                }
                let key = format!("{kind}/{namespace}/{name}");
                let spec = live.specs.get(&key).cloned().unwrap_or_else(|| json!({}));
                seen.lock().map_err(|e| wrong(e.to_string()))?.insert(key);
                Ok(minijinja::Value::from(minijinja::value::Serde(spec)))
            });
            looked
        })
    }

    /// The render, with `lookup` put in the environment by `equip` (which gives the keys it
    /// is asked for).
    fn render_with(
        &self,
        release: Release<'_>,
        layers: &[Value],
        equip: impl FnOnce(&mut Environment<'_>) -> Looked,
    ) -> Fallible<Rendered> {
        named("package.yaml: the name", &self.meta.name)?;
        named("the release's name", release.name)?;
        named("the release's namespace", release.namespace)?;
        let values = self.values(layers)?;
        let labels = json!({ LABEL_RELEASE: release.name, LABEL_PACKAGE: self.meta.name });
        let context = json!({
            "values": values,
            "release": { "name": release.name, "namespace": release.namespace },
            "package": { "name": self.meta.name, "version": self.meta.version },
            "name": full_name(release.name, &self.meta.name),
            "labels": labels,
        });
        let mut environment = self.environment()?;
        let looked = equip(&mut environment);
        let rendered = std::cell::Cell::new(0);
        let text = |path: &str| -> Fallible<String> {
            let template = environment.get_template(path).map_err(|e| template_error(&e))?;
            let text = template.render(minijinja::value::Serde(&context));
            let text = text.map_err(|e| template_error(&e))?;
            if text.len() > TEXT_LIMIT {
                return Err(format!("{path}: renders to more than {TEXT_LIMIT} bytes"));
            }
            rendered.set(rendered.get() + text.len());
            if rendered.get() > RENDERED_LIMIT {
                return Err(format!(
                    "{path}: the templates render to more than {RENDERED_LIMIT} bytes in all"
                ));
            }
            Ok(text)
        };
        let mut resources: Vec<Resource> = Vec::new();
        let mut keys = std::collections::BTreeSet::new();
        // One resource a file gave: in the release's namespace unless it says another,
        // labelled as the release's, and no other file's too.
        let mut add = |path: &str, mut resource: Resource, placed: bool| -> Fallible<()> {
            if !placed && kith_api::kind(&resource.kind).is_some_and(|kind| kind.namespaced) {
                resource.metadata.namespace = Some(release.namespace.to_string());
            }
            for (label, value) in labels.as_object().into_iter().flatten() {
                let value = value.as_str().unwrap_or_default().to_string();
                resource.metadata.labels.insert(label.clone(), value);
            }
            let key = resource.key();
            if keys.contains(&key) {
                return Err(format!("{path}: {key} is rendered twice"));
            }
            if keys.len() == RESOURCES_LIMIT {
                return Err(format!(
                    "{path}: the package renders to more than {RESOURCES_LIMIT} resources"
                ));
            }
            keys.insert(key);
            resources.push(resource);
            Ok(())
        };
        let placed = |document: &kith_yaml::Node| {
            let metadata = document.get("metadata");
            metadata.is_some_and(|metadata| metadata.get("namespace").is_some())
        };
        let is_resource = |path: &&String| {
            let name = path.trim_start_matches("templates/");
            !name.starts_with('_') && [".yaml", ".yml", ".kith"].iter().any(|end| name.ends_with(end))
        };
        // A `.kith` file has the names a template has, and imports only the package's files.
        let names = context.as_object().into_iter().flatten();
        let names: Vec<(&str, Value)> = names.map(|(name, value)| (name.as_str(), value.clone())).collect();
        let file = |name: &str| {
            self.templates
                .get(name)
                .cloned()
                .ok_or_else(|| "the package has no such file".to_string())
        };
        for path in self.templates.keys().filter(is_resource) {
            if path.ends_with(".kith") {
                let output = kith_lang::eval(path, &file, &names).map_err(|e| e.to_string())?;
                for document in &output.docs {
                    let resource = Resource::from_node(document).map_err(|e| output.said(document, &e).to_string())?;
                    add(path, resource, placed(document))?;
                }
                continue;
            }
            let rendered = text(path)?;
            let shown = |e: kith_yaml::Error| format!("what {path} renders to:\n{}", e.render(path, &rendered));
            for document in kith_yaml::parse(&rendered).map_err(shown)? {
                let resource = Resource::from_node(&document).map_err(shown)?;
                add(path, resource, placed(&document))?;
            }
        }
        let notes = self.notes.as_ref().map(|_| text(NOTES)).transpose()?;
        let looked = std::mem::take(&mut *looked.lock().map_err(|e| e.to_string())?);
        Ok(Rendered {
            resources,
            notes,
            looked,
        })
    }

    /// Everything wrong with the package that shows without installing it: what
    /// `package.yaml` says, the schema, and what the templates render to with the
    /// default values.
    pub fn lint(&self) -> Vec<String> {
        let mut wrong = Vec::new();
        let numbers = self.meta.version.split(['-', '+']).next().unwrap_or_default();
        let numeric = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
        if numbers.split('.').count() != 3 || !numbers.split('.').all(numeric) {
            let version = &self.meta.version;
            wrong.push(format!("package.yaml: version `{version}` is not like 1.2.3"));
        }
        if let Some(asked) = &self.meta.kith_version {
            if semver::VersionReq::parse(asked).is_err() {
                wrong.push(format!(
                    "package.yaml: kithVersion `{asked}` is not a version range like >=1.2"
                ));
            }
        }
        let name = json!({ "apiVersion": "kith.dev/v1", "kind": "Package", "metadata": { "name": self.meta.name }, "spec": { "version": "0.0.0" } });
        let named = serde_json::from_value::<Resource>(name).map_err(|e| e.to_string());
        if let Err(e) = named.and_then(Resource::validated) {
            wrong.push(format!("package.yaml: {e}"));
        }
        if let Some(schema) = &self.schema {
            unknown_keywords(schema, "values.schema.json", &mut wrong);
        }
        let release = Release {
            name: "lint",
            namespace: "default",
        };
        match self.render(release, &[]) {
            Ok(rendered) if rendered.resources.is_empty() => wrong.push("templates: nothing is rendered".into()),
            Ok(_) => {}
            Err(e) => wrong.push(e),
        }
        wrong
    }
}

#[cfg(test)]
mod tests;
