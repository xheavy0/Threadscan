from threadscan.components import glob_match, select_components, slugify, split_components
from threadscan.config import AutoSplit, ComponentsConfig, DEFAULT_EXCLUDES, ExplicitComponent
from threadscan.repo import changed_files, list_files

FILES = [
    "backend/src/main/java/com/x/App.java",
    "backend/src/main/java/com/x/auth/Login.java",
    "backend/src/main/java/com/x/auth/sso/Saml.java",
    "backend/src/main/java/com/x/storage/Store.java",
    "backend/src/main/java/com/x/storage/s3/S3.java",
    "src/components/vendors/Portal.tsx",
    "src/rbac.ts",
    "deploy/nginx.conf",
    "docs/guide.md",
    "package.json",
    "dist/bundle.min.js",
]


def cfg(**kw) -> ComponentsConfig:
    base = dict(
        exclude=DEFAULT_EXCLUDES + ["docs/**"],
        auto=[AutoSplit("backend/src/main/java/com/x", 1), AutoSplit("src", 1)],
        explicit=[ExplicitComponent("deploy", ["deploy/**"], priority=3)],
    )
    base.update(kw)
    return ComponentsConfig(**base)


def by_name(comps):
    return {c.name: c for c in comps}


def test_glob_semantics():
    assert glob_match("deploy/**", "deploy/a/b.conf")
    assert glob_match("**/node_modules/**", "node_modules/x/i.js")
    assert glob_match("**/node_modules/**", "a/node_modules/x/i.js")
    assert glob_match("src/*.ts", "src/rbac.ts")
    assert not glob_match("src/*.ts", "src/lib/a.ts")
    assert glob_match("**/*.md", "README.md") and glob_match("**/*.md", "a/b/c.md")
    assert not glob_match("a?c", "a/c")


def test_auto_split_by_depth_and_root_files():
    comps = by_name(split_components(FILES, cfg()))
    assert set(comps["backend/src/main/java/com/x/auth"].files) == {
        "backend/src/main/java/com/x/auth/Login.java",
        "backend/src/main/java/com/x/auth/sso/Saml.java",  # deeper files fold into depth-1 dir
    }
    assert comps["backend/src/main/java/com/x"].files == ["backend/src/main/java/com/x/App.java"]
    assert comps["src/components"].files == ["src/components/vendors/Portal.tsx"]
    assert comps["src"].files == ["src/rbac.ts"]


def test_deeper_auto_root_wins_and_depth_two():
    c = cfg(auto=[AutoSplit("src", 1), AutoSplit("src/components", 1), AutoSplit("backend/src/main/java/com/x", 2)])
    comps = by_name(split_components(FILES, c))
    assert "src/components/vendors" in comps
    assert "backend/src/main/java/com/x/storage/s3" in comps
    assert "backend/src/main/java/com/x/storage" in comps  # Store.java sits at depth 1


def test_explicit_takes_precedence_and_first_match_wins():
    c = cfg(explicit=[
        ExplicitComponent("auth", ["backend/**/auth/**"], priority=10),
        ExplicitComponent("all-java", ["backend/**"]),
    ])
    comps = by_name(split_components(FILES, c))
    assert comps["auth"].kind == "explicit" and len(comps["auth"].files) == 2
    assert "backend/src/main/java/com/x/auth" not in comps
    assert len(comps["all-java"].files) == 3


def test_excludes_and_leftover():
    comps = by_name(split_components(FILES, cfg()))
    every = [f for c in comps.values() for f in c.files]
    assert "docs/guide.md" not in every and "dist/bundle.min.js" not in every
    assert comps["misc"].files == ["package.json"] and comps["misc"].kind == "leftover"
    comps2 = by_name(split_components(FILES, cfg(leftover=None)))
    assert "misc" not in comps2


def test_each_file_in_at_most_one_component():
    comps = split_components(FILES, cfg())
    every = [f for c in comps for f in c.files]
    assert len(every) == len(set(every))


def test_empty_explicit_components_are_dropped():
    comps = by_name(split_components(FILES, cfg(explicit=[ExplicitComponent("nothing", ["nope/**"])])))
    assert "nothing" not in comps


def test_select_full_orders_by_priority_then_name_and_limits():
    comps = split_components(FILES, cfg())
    sel = select_components(comps, None)
    assert sel[0].name == "deploy"  # priority 3
    assert sel[-1].name == "misc"  # leftover priority -10
    assert len(select_components(comps, None, max_components=2)) == 2


def test_select_diff_mode_only_touched_components():
    comps = split_components(FILES, cfg())
    sel = select_components(comps, ["backend/src/main/java/com/x/auth/Login.java", "docs/guide.md"])
    assert [c.name for c in sel] == ["backend/src/main/java/com/x/auth"]
    assert sel[0].changed_files == ["backend/src/main/java/com/x/auth/Login.java"]
    assert select_components(comps, []) == []


def test_select_only():
    comps = split_components(FILES, cfg())
    sel = select_components(comps, None, only=["src"])
    assert [c.name for c in sel] == ["src"]
    sel = select_components(comps, None, only=[comps[0].slug])
    assert sel[0].name == comps[0].name


def test_slug_is_filesystem_and_docker_safe_and_unique():
    a, b = slugify("backend/src/A_b"), slugify("backend/src/a-b")
    assert a != b
    assert all(ch.isalnum() or ch == "-" for ch in a) and a == a.lower()


def test_against_a_real_git_repo(sample_repo):
    files = list_files(sample_repo)
    assert "node_modules/x/index.js" not in files  # gitignored
    comps = split_components(files, cfg(auto=[AutoSplit("backend/src/main/java/com/x", 1), AutoSplit("src", 1)]))
    changed = changed_files(sample_repo, "HEAD~1")
    assert changed == ["backend/src/main/java/com/x/auth/Login.java", "backend/src/main/java/com/x/auth/Mfa.java"]
    sel = select_components(comps, changed)
    assert [c.name for c in sel] == ["backend/src/main/java/com/x/auth"]
