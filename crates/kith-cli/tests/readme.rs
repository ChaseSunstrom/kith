//! README.md says what exists: these fail when it stops being so.
//
// ponytail: this reads what can be read by a program: the examples, one count, the
// links, the paths, and phrases that were once stale. Whether a sentence is true is
// still read by a person; a markdown parser if the fences ever nest. An example is
// read and validated as `kith lint` does without a store: what only a KindDefinition
// or another resource could refuse is not seen.

use kith_api::{KINDS, Resource};
use std::path::Path;

const README: &str = include_str!("../../../README.md");

fn root() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
}

/// The fenced blocks tagged `tag`, each with the line it starts on.
fn blocks(tag: &str) -> Vec<(usize, String)> {
    let (mut out, mut open) = (Vec::new(), None::<(usize, String)>);
    for (number, line) in README.lines().enumerate() {
        match (&mut open, line.trim_start().strip_prefix("```")) {
            (None, Some(said)) if said.trim() == tag => open = Some((number + 1, String::new())),
            (Some(_), Some(_)) => out.extend(open.take()),
            (Some((_, text)), None) => *text += &format!("{line}\n"),
            (None, _) => {}
        }
    }
    assert!(open.is_none(), "README.md: a ```{tag} block is not closed");
    assert!(
        !README.contains("```yml"),
        "README.md: tag an example ```yaml, or it is not checked"
    );
    out
}

/// Blocks that are not a whole resource, and so are not checked: two `spec:` parts shown
/// inside a list, and the installer's file.
const PARTS: usize = 3;

#[test]
fn readme_examples_are_taken_by_this_build() {
    let (mut whole, mut parts, mut wrong) = (0, 0, Vec::new());
    for (line, text) in blocks("yaml") {
        if !text.lines().any(|line| line.starts_with("apiVersion:")) {
            parts += 1;
            continue;
        }
        match Resource::from_source(&text) {
            Err(e) => wrong.push(format!("README.md:{line}: {e}")),
            Ok(found) => {
                for resource in found {
                    match resource.map_err(|e| e.to_string()).and_then(Resource::validated) {
                        Ok(_) => whole += 1,
                        Err(e) => wrong.push(format!("README.md:{line}: {e}")),
                    }
                }
            }
        }
    }
    assert!(wrong.is_empty(), "examples this build refuses:\n{}", wrong.join("\n"));
    assert!(whole > 0, "README.md has no yaml example left: this test read nothing");
    assert_eq!(
        parts, PARTS,
        "yaml blocks with no apiVersion (a part is not checked: make it whole, or count it here)"
    );
}

#[test]
fn readme_counts_the_kinds_there_are() {
    let before = |(at, _)| README[..at].rsplit(' ').next().unwrap();
    let said: Vec<&str> = README
        .match_indices(" built-in kinds")
        .map(before)
        .filter(|word| word.parse::<usize>().is_ok())
        .collect();
    assert_eq!(
        said,
        [KINDS.len().to_string()],
        "README.md says how many built-in kinds there are, once, as \"the N built-in kinds\""
    );
}

#[test]
fn readme_says_nothing_that_was_true_once() {
    for stale in [
        "(in progress)",
        "Status: one node",
        "is being built",
        "come next",
        "Phase ",
    ] {
        let at = README.lines().position(|line| line.contains(stale));
        assert_eq!(
            at.map(|at| at + 1),
            None,
            "README.md: {stale:?} is from when the plan was not done"
        );
    }
}

/// The table beside k3s is the one `sh ci/compare.sh` wrote down: not numbers typed in.
#[test]
fn readme_carries_the_measured_comparison() {
    let measured = std::fs::read_to_string(root().join("ci/compare.txt")).expect("ci/compare.txt");
    // (The table and the two lines under it; over it is what was run, under it every run.)
    let said: Vec<&str> = measured
        .lines()
        .skip_while(|line| !line.starts_with('|'))
        .take_while(|line| !line.starts_with("The runs"))
        .filter(|line| !line.is_empty())
        .collect();
    assert!(said.len() > 6, "ci/compare.txt has no table: {measured}");
    let section = README
        .split("\n## Beside k3s\n")
        .nth(1)
        .expect("README.md: ## Beside k3s");
    let section = section.split("\n## ").next().unwrap_or(section);
    for line in &said {
        assert!(
            section.contains(line),
            "README.md's table beside k3s lacks, or has another, {line}"
        );
    }
    // (And no row of its own: a line of the README's table that the file does not have.)
    for row in section.lines().filter(|line| line.starts_with('|')) {
        assert!(
            said.contains(&row),
            "README.md's table beside k3s has a row ci/compare.txt lacks: {row}"
        );
    }
}

#[test]
fn readme_links_and_paths_lead_somewhere() {
    let mut seen = 0;
    // [text](path) and <img src="path">, where the path is a file of this repository.
    for (open, close) in [("](", ')'), ("src=\"", '"')] {
        for (at, _) in README.match_indices(open) {
            let rest = &README[at + open.len()..];
            let link = &rest[..rest.find(close).unwrap_or(0)];
            let path = link.split('#').next().unwrap();
            if let Some(heading) = link.strip_prefix('#') {
                // (As GitHub names a heading: lower case, spaces to hyphens, the rest dropped.)
                let named = |line: &str| {
                    let title = line.trim_start_matches('#').trim().to_lowercase().replace(' ', "-");
                    title
                        .chars()
                        .filter(|c| c.is_alphanumeric() || "-_".contains(*c))
                        .collect::<String>()
                };
                // (A `#` line inside a fence is a comment of the example, not a heading.)
                let mut fenced = false;
                let found = README.lines().any(|line| {
                    fenced ^= line.trim_start().starts_with("```");
                    !fenced && line.starts_with('#') && named(line) == heading
                });
                assert!(found, "README.md links to its heading {link}, and has none");
                seen += 1;
                continue;
            }
            if path.is_empty() || link.contains("://") || link.starts_with("mailto:") {
                continue;
            }
            assert!(
                root().join(path).exists(),
                "README.md links to {link}, which is not there"
            );
            seen += 1;
        }
    }
    // The Layout table: each row's first cell is a path.
    let layout = README
        .split("\n## Layout\n")
        .nth(1)
        .expect("README.md has a Layout section");
    let layout = layout.split("\n## ").next().unwrap();
    let mut rows = Vec::new();
    for row in layout.lines().filter_map(|line| line.strip_prefix("| `")) {
        let path = row.split('`').next().unwrap();
        assert!(
            root().join(path).exists(),
            "README.md's Layout names {path}, which is not there"
        );
        rows.push(path.trim_end_matches('/'));
    }
    // And each directory of the repository has a row; `crates` and `sdk`, each one in them.
    let dirs = |dir: &Path| -> Vec<String> {
        let entries = std::fs::read_dir(dir).unwrap().map(Result::unwrap);
        let dirs = entries.filter(|entry| entry.file_type().unwrap().is_dir());
        dirs.map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect()
    };
    for top in dirs(root())
        .into_iter()
        .filter(|name| !name.starts_with('.') && name != "target")
    {
        let inner = ["crates", "sdk"].contains(&top.as_str());
        let names = if inner {
            dirs(&root().join(&top))
                .into_iter()
                .map(|name| format!("{top}/{name}"))
                .collect()
        } else {
            vec![top]
        };
        for name in names {
            assert!(
                rows.contains(&name.as_str()),
                "README.md's Layout has no row for {name}"
            );
        }
    }
    assert!(
        seen > 5 && rows.len() > 10,
        "README.md: {seen} links and {} Layout rows were read: too few to be all",
        rows.len()
    );
}

/// kith's own language as README.md shows it: the file it shows gives the resources it
/// says, the mistake it shows is refused in those very words, the package's file is the
/// one in the repository, and the builtins it lists are the ones there are.
#[test]
fn readme_shows_the_language_as_it_is() {
    let shown = blocks("kith");
    assert_eq!(shown.len(), 2, "README.md: a whole file, and the package's");
    let given = |text: String| {
        let load = move |name: &str| match name {
            "web.kith" => Ok(text.clone()),
            _ => Err("no such file".to_string()),
        };
        kith_lang::resources("web.kith", &load, &[])
    };
    let said = |wrong: Vec<kith_lang::Error>| wrong.iter().map(|wrong| wrong.to_string()).collect::<String>();
    let found = given(shown[0].1.clone()).unwrap_or_else(|wrong| panic!("README.md:{}:\n{}", shown[0].0, said(wrong)));
    let keys: Vec<String> = found.iter().map(Resource::key).collect();
    assert_eq!(keys, ["Workload/default/web", "Service/default/web"]);

    let wrong = given(shown[0].1.replace("replicas: 3", "replicas: \"three\"")).map(|_| ());
    let wrong = said(wrong.expect_err("a string for replicas"));
    let block = format!("```\n{}\n```", wrong.trim_end());
    assert!(
        README.contains(&block),
        "README.md shows another refusal than:\n{block}"
    );

    let service = std::fs::read_to_string(root().join("packages/web-kith/templates/service.kith")).unwrap();
    assert_eq!(
        shown[1].1, service,
        "README.md shows another service.kith than packages/web-kith has"
    );

    for (name, usage) in kith_lang::BUILTINS {
        let (call, what) = usage.split_once(": ").expect("how it is called, and what it gives");
        assert!(
            README.contains(&format!("| `{call}` | {what} |")),
            "README.md does not list {name} as: {usage}"
        );
    }
    let listed = README
        .lines()
        .filter(|line| line.starts_with("| `") && line.contains("(") && line.contains(")` | "));
    let section = README
        .split("\n## kith's own language\n")
        .nth(1)
        .expect("README.md: ## kith's own language");
    let section = section.split("\n## ").next().unwrap_or(section);
    assert_eq!(
        listed.filter(|line| section.contains(line)).count(),
        kith_lang::BUILTINS.len(),
        "README.md lists a builtin there is not"
    );
}
