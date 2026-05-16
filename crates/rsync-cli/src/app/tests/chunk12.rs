use super::*;

// Chunk 12: Advanced Transfer Features tests

#[test]
fn plan_renders_compare_dest() {
    let plan = parse_and_render([
        "rsync-win",
        "--plan",
        "--compare-dest=/tmp/basis",
        "src",
        "dst",
    ]);
    assert!(plan.contains("compare dest: /tmp/basis"));
    assert!(plan.contains("--compare-dest=/tmp/basis is represented in the execution plan"));
}

#[test]
fn plan_renders_multiple_compare_dest() {
    let plan = parse_and_render([
        "rsync-win",
        "--plan",
        "--compare-dest=/tmp/basis1",
        "--compare-dest=/tmp/basis2",
        "src",
        "dst",
    ]);
    assert!(plan.contains("compare dest: /tmp/basis1 /tmp/basis2"));
}

#[test]
fn plan_renders_copy_dest() {
    let plan = parse_and_render([
        "rsync-win",
        "--plan",
        "--copy-dest=/tmp/basis",
        "src",
        "dst",
    ]);
    assert!(plan.contains("copy dest: /tmp/basis"));
}

#[test]
fn plan_renders_link_dest() {
    let plan = parse_and_render([
        "rsync-win",
        "--plan",
        "--link-dest=/tmp/basis",
        "src",
        "dst",
    ]);
    assert!(plan.contains("link dest: /tmp/basis"));
}

#[test]
fn plan_renders_sparse() {
    let plan = parse_and_render(["rsync-win", "--plan", "-S", "src", "dst"]);
    assert!(plan.contains("sparse: true"));
    assert!(plan.contains("FSCTL_SET_SPARSE_FILE"));
}

#[test]
fn plan_renders_preallocate() {
    let plan = parse_and_render(["rsync-win", "--plan", "--preallocate", "src", "dst"]);
    assert!(plan.contains("preallocate: true"));
}

#[test]
fn plan_warns_sparse_preallocate_overlap() {
    let plan = parse_and_render(["rsync-win", "--plan", "-S", "--preallocate", "src", "dst"]);
    assert!(plan.contains("--sparse and --preallocate together"));
}

#[test]
fn plan_renders_fuzzy() {
    let plan = parse_and_render(["rsync-win", "--plan", "-y", "src", "dst"]);
    assert!(plan.contains("fuzzy: true"));
}

#[test]
fn plan_renders_copy_as() {
    let plan = parse_and_render([
        "rsync-win",
        "--plan",
        "--copy-as=Administrator",
        "src",
        "dst",
    ]);
    assert!(plan.contains("copy-as: Administrator"));
}

#[test]
fn plan_renders_super() {
    let plan = parse_and_render(["rsync-win", "--plan", "--super", "src", "dst"]);
    assert!(plan.contains("super: true"));
}

#[test]
fn plan_renders_no_super() {
    let plan = parse_and_render(["rsync-win", "--plan", "--no-super", "src", "dst"]);
    assert!(!plan.contains("super: true"));
}

#[test]
fn plan_renders_negated_chunk12_flags() {
    let plan = parse_and_render([
        "rsync-win",
        "--plan",
        "-S",
        "--no-sparse",
        "--preallocate",
        "--no-preallocate",
        "-y",
        "--no-fuzzy",
        "src",
        "dst",
    ]);

    assert!(!plan.contains("sparse: true"), "{plan}");
    assert!(!plan.contains("preallocate: true"), "{plan}");
    assert!(!plan.contains("fuzzy: true"), "{plan}");
    assert!(!plan.contains("W_UNIMPLEMENTED_OPTION"), "{plan}");
}

#[test]
fn plan_renders_write_batch() {
    let plan = parse_and_render([
        "rsync-win",
        "--plan",
        "--write-batch=/tmp/batch.bin",
        "src",
        "dst",
    ]);
    assert!(plan.contains("write-batch: /tmp/batch.bin"));
}

#[test]
fn plan_renders_read_batch() {
    let plan = parse_and_render([
        "rsync-win",
        "--plan",
        "--read-batch=/tmp/batch.bin",
        "src",
        "dst",
    ]);
    assert!(plan.contains("read-batch: /tmp/batch.bin"));
}

#[test]
fn plan_errors_on_write_and_only_write_batch_together() {
    let plan = parse_and_render([
        "rsync-win",
        "--plan",
        "--write-batch=a",
        "--only-write-batch=b",
        "src",
        "dst",
    ]);
    assert!(plan.contains("--write-batch and --only-write-batch cannot both be specified"));
}

#[test]
fn plan_errors_on_write_and_read_batch_together() {
    let plan = parse_and_render([
        "rsync-win",
        "--plan",
        "--write-batch=a",
        "--read-batch=b",
        "src",
        "dst",
    ]);
    assert!(plan.contains("--write-batch and --read-batch cannot both be specified"));
}

#[test]
fn plan_shows_all_chunk12_options_together() {
    let plan = parse_and_render([
        "rsync-win",
        "--plan",
        "--compare-dest=/tmp/a",
        "--copy-dest=/tmp/b",
        "--link-dest=/tmp/c",
        "-S",
        "--preallocate",
        "-y",
        "src",
        "dst",
    ]);
    assert!(plan.contains("compare dest: /tmp/a"));
    assert!(plan.contains("copy dest: /tmp/b"));
    assert!(plan.contains("link dest: /tmp/c"));
    assert!(plan.contains("sparse: true"));
    assert!(plan.contains("preallocate: true"));
    assert!(plan.contains("fuzzy: true"));
}
