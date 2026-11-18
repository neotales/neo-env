//! Semantic version comparison shared by the project and global lifecycle
//! implementations. Kept free of filesystem and process effects.

pub(super) fn compare_versions(left: &str, right: &str) -> std::cmp::Ordering {
    let left = left.trim().trim_start_matches(['v', 'V']);
    let right = right.trim().trim_start_matches(['v', 'V']);
    let (left_core, left_pre) = split_prerelease(left);
    let (right_core, right_pre) = split_prerelease(right);
    let left_parts = version_parts(left_core);
    let right_parts = version_parts(right_core);
    let count = left_parts.len().max(right_parts.len());
    for index in 0..count {
        let left_part = left_parts.get(index).copied().flatten().unwrap_or(0);
        let right_part = right_parts.get(index).copied().flatten().unwrap_or(0);
        let ordering = left_part.cmp(&right_part);
        if ordering != std::cmp::Ordering::Equal {
            return ordering;
        }
    }
    match (left_pre, right_pre) {
        (None, None) => left_core.cmp(right_core),
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (Some(_), None) => std::cmp::Ordering::Less,
        (Some(left), Some(right)) => {
            compare_prerelease(left, right).then_with(|| left_core.cmp(right_core))
        }
    }
}

pub(super) fn split_prerelease(value: &str) -> (&str, Option<&str>) {
    value
        .split_once('-')
        .map_or((value, None), |(core, prerelease)| (core, Some(prerelease)))
}

pub(super) fn version_parts(value: &str) -> Vec<Option<u64>> {
    value
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty())
        .map(|part| part.parse::<u64>().ok())
        .collect()
}

pub(super) fn compare_prerelease(left: &str, right: &str) -> std::cmp::Ordering {
    let left_parts = left.split(['.', '+']);
    let right_parts = right.split(['.', '+']);
    let mut left_parts = left_parts.peekable();
    let mut right_parts = right_parts.peekable();
    loop {
        match (left_parts.next(), right_parts.next()) {
            (None, None) => return std::cmp::Ordering::Equal,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (Some(left), Some(right)) => {
                let ordering = match (left.parse::<u64>(), right.parse::<u64>()) {
                    (Ok(left), Ok(right)) => left.cmp(&right),
                    (Ok(_), Err(_)) => std::cmp::Ordering::Greater,
                    (Err(_), Ok(_)) => std::cmp::Ordering::Less,
                    (Err(_), Err(_)) => left.cmp(right),
                };
                if ordering != std::cmp::Ordering::Equal {
                    return ordering;
                }
            }
        }
    }
}
