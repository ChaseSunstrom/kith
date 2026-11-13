//! Packages (PLAN.md §4.8): a directory of resource templates with default values,
//! rendered for a release into resources.
//!
//! ```text
//! package.yaml          name, version, description, kithVersion, dependencies
//! values.yaml           the default values
//! values.schema.json    what values may be (optional)
//! templates/*.yaml      resources, as templates; `_name` files are only included
//! NOTES                 what to tell whoever installed it, a template too (optional)
//! ```
//!
//! Templates are Jinja (minijinja). They see `values`, `release.name`,
//! `release.namespace`, `package.name`, `package.version`, `name` (a name for the
//! release's resources) and `labels` (what every resource of the release is labelled
//! with); the filter `toYaml`, and `required(value, "why")`.
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
    /// unless its template says another.
    pub fn render(&self, release: Release<'_>, layers: &[Value]) -> Fallible<Rendered> {
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
        let environment = self.environment()?;
        let text = |path: &str| -> Fallible<String> {
            let template = environment.get_template(path).map_err(|e| template_error(&e))?;
            let text = template.render(minijinja::value::Serde(&context));
            match text.map_err(|e| template_error(&e))? {
                text if text.len() > TEXT_LIMIT => Err(format!("{path}: renders to more than {TEXT_LIMIT} bytes")),
                text => Ok(text),
            }
        };
        let mut resources = Vec::new();
        let is_resource = |path: &&String| {
            let name = path.trim_start_matches("templates/");
            !name.starts_with('_') && (name.ends_with(".yaml") || name.ends_with(".yml"))
        };
        for path in self.templates.keys().filter(is_resource) {
            let rendered = text(path)?;
            let shown = |e: kith_yaml::Error| format!("what {path} renders to:\n{}", e.render(path, &rendered));
            for document in kith_yaml::parse(&rendered).map_err(shown)? {
                let placed = document
                    .get("metadata")
                    .is_some_and(|metadata| metadata.get("namespace").is_some());
                let mut resource = Resource::from_node(&document).map_err(shown)?;
                if !placed && kith_api::kind(&resource.kind).is_some_and(|kind| kind.namespaced) {
                    resource.metadata.namespace = Some(release.namespace.to_string());
                }
                let Value::Object(labels) = &labels else {
                    unreachable!("an object")
                };
                for (label, value) in labels {
                    let value = value.as_str().unwrap_or_default().to_string();
                    resource.metadata.labels.insert(label.clone(), value);
                }
                if let Some(twin) = resources.iter().find(|other: &&Resource| other.key() == resource.key()) {
                    return Err(format!("{path}: {} is rendered twice", twin.key()));
                }
                resources.push(resource);
            }
        }
        let notes = self.notes.as_ref().map(|_| text(NOTES)).transpose()?;
        Ok(Rendered { resources, notes })
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
