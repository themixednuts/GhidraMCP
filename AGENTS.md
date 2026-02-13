# AGENTS

- When reasoning about or modifying tool logic, always use official Ghidra documentation as the primary reference source.

## Git: Splitting Commits by Intent

When a single working tree has changes spanning multiple features, use `git apply --cached` to stage individual hunks non-interactively (no `-i` / `-p` needed).

### Workflow

```bash
# 1. Unstage everything to start clean
git restore --staged .

# 2. For files that belong entirely to one commit, just git add them
git add path/to/new_file.rs path/to/single_intent_change.rs

# 3. For shared files (changes from multiple features in one file),
#    write a patch with only the hunks you want staged:
cat > /tmp/feature_a.patch << 'PATCH'
diff --git a/shared/file.rs b/shared/file.rs
--- a/shared/file.rs
+++ b/shared/file.rs
@@ -10,6 +10,7 @@ existing context line
 more context
 another context line
+pub mod feature_a;
 trailing context
 more trailing context

PATCH

# 4. Stage just those hunks (--cached = index only, working tree untouched)
git apply --cached /tmp/feature_a.patch

# 5. Commit, then repeat for the next intent
git commit -m "feat(a): description"
```

### Tips

- **Get the full diff first** for reference: `git diff path/to/shared_file.rs > /tmp/full.patch`
- **Context lines matter** — include 3 lines of surrounding context so git can locate the hunk
- **Trailing newline required** — patches must end with a blank line after the last hunk
- **Line numbers are fuzzy** — git uses context matching, so `@@` line numbers don't need to be exact
- **New files** can't use `apply --cached` — just `git add` them directly
- **Verify before committing**: `git diff --cached --stat` to confirm only intended files/hunks are staged
