use dcg_cli::packs::PackRegistry;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

fn read_repo_file(path: &str) -> std::io::Result<String> {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().expect("manifest dir has parent").parent().expect("crates dir has parent");
    let full_path = repo_root.join(path);
    std::fs::read_to_string(&full_path)
}

fn registry_pack_ids() -> BTreeSet<&'static str> {
    PackRegistry::new().all_pack_ids().into_iter().collect()
}

fn registry_category_counts() -> BTreeMap<String, usize> {
    let registry = PackRegistry::new();
    registry
        .all_categories()
        .into_iter()
        .map(|category| (category.clone(), registry.packs_in_category(category).len()))
        .collect()
}

fn docs_pack_category_counts(docs: &str) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();

    for line in docs.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("| [") {
            continue;
        }

        let cells: Vec<&str> = trimmed
            .split('|')
            .map(str::trim)
            .filter(|cell| !cell.is_empty())
            .collect();

        if cells.len() < 3 {
            continue;
        }

        let Some(category) = cells[0]
            .strip_prefix('[')
            .and_then(|cell| cell.split_once("]("))
            .map(|(category, _)| category)
        else {
            continue;
        };

        let Ok(count) = cells[1].parse::<usize>() else {
            continue;
        };

        assert!(
            counts.insert(category.to_string(), count).is_none(),
            "docs/packs/README.md contains duplicate category row for {category}"
        );
    }

    counts
}

#[test]
fn docs_packs_index_matches_registry_ids() -> std::io::Result<()> {
    let expected = registry_pack_ids();
    let docs = read_repo_file("docs/packs/README.md")?;

    let mut found: BTreeSet<String> = BTreeSet::new();
    for line in docs.lines() {
        let trimmed = line.trim();
        // Match old format: - `pack_id`
        if let Some(rest) = trimmed
            .strip_prefix("- `")
            .and_then(|rest| rest.strip_suffix('`'))
        {
            found.insert(rest.to_string());
        }
        // Match new format: - [`pack_id`](file.md#anchor)
        else if let Some(rest) = trimmed.strip_prefix("- [`") {
            if let Some(pack_id) = rest.split('`').next() {
                found.insert(pack_id.to_string());
            }
        }
    }

    let missing: Vec<String> = expected
        .iter()
        .filter(|id| !found.contains(**id))
        .map(ToString::to_string)
        .collect();
    let extra: Vec<String> = found
        .iter()
        .filter(|id| !expected.contains(id.as_str()))
        .cloned()
        .collect();

    assert!(
        missing.is_empty(),
        "docs/packs/README.md is missing pack ids:\n{}",
        missing.join("\n")
    );
    assert!(
        extra.is_empty(),
        "docs/packs/README.md contains unknown pack ids:\n{}",
        extra.join("\n")
    );

    Ok(())
}

#[test]
fn docs_packs_category_counts_match_registry() -> std::io::Result<()> {
    let expected = registry_category_counts();
    let docs = read_repo_file("docs/packs/README.md")?;
    let found = docs_pack_category_counts(&docs);

    let missing: Vec<String> = expected
        .keys()
        .filter(|category| !found.contains_key(*category))
        .cloned()
        .collect();
    let extra: Vec<String> = found
        .keys()
        .filter(|category| !expected.contains_key(*category))
        .cloned()
        .collect();
    let mismatched: Vec<String> = expected
        .iter()
        .filter_map(|(category, expected_count)| {
            let found_count = found.get(category)?;
            (found_count != expected_count).then(|| {
                format!("{category}: docs has {found_count}, registry has {expected_count}")
            })
        })
        .collect();

    let mut errors = Vec::new();
    if !missing.is_empty() {
        errors.push(format!("Missing category rows:\n{}", missing.join("\n")));
    }
    if !extra.is_empty() {
        errors.push(format!("Unknown category rows:\n{}", extra.join("\n")));
    }
    if !mismatched.is_empty() {
        errors.push(format!("Stale category counts:\n{}", mismatched.join("\n")));
    }

    if !errors.is_empty() {
        let mut fix_hint = String::from("\n\nExpected table rows (copy to fix):\n");
        for (category, count) in &expected {
            writeln!(fix_hint, "| [{category}]({category}.md) | {count} | ... |")
                .expect("writing to String cannot fail");
        }
        panic!(
            "docs/packs/README.md category table is out of sync:\n{}\n{}",
            errors.join("\n\n"),
            fix_hint
        );
    }

    Ok(())
}

#[test]
fn docs_total_pack_count_matches_registry() -> std::io::Result<()> {
    let registry = PackRegistry::new();
    let total_packs = registry.all_pack_ids().len();
    let total_categories = registry.all_categories().len();
    let docs = read_repo_file("docs/packs/README.md")?;

    let category_counts = registry_category_counts();
    let sum_of_category_counts: usize = category_counts.values().sum();

    assert_eq!(
        sum_of_category_counts, total_packs,
        "Sum of category counts ({sum_of_category_counts}) != total pack count ({total_packs}). \
         A pack may be missing from its category registration."
    );

    let found_categories = docs_pack_category_counts(&docs);
    assert_eq!(
        found_categories.len(),
        total_categories,
        "docs/packs/README.md has {} categories but registry has {total_categories}",
        found_categories.len()
    );

    Ok(())
}

#[test]
fn readme_lists_all_registry_pack_ids() -> std::io::Result<()> {
    let expected = registry_pack_ids();
    let readme = read_repo_file("README.md")?;

    let missing: Vec<String> = expected
        .iter()
        .filter(|id| !readme.contains(&format!("`{id}`")))
        .map(ToString::to_string)
        .collect();

    assert!(
        missing.is_empty(),
        "README.md is missing pack ids:\n{}",
        missing.join("\n")
    );

    Ok(())
}
