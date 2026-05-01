# xbow findings export

Export findings for an XBOW asset to multiple formats.

## Install

```
uv sync
```

Place your API token in `token.txt` in this directory, or set `XBOW_API_KEY` in your environment.

## Usage

```
uv run main.py <asset_id> [--print] [--csv] [--json] [--pdf] [--markdown]
```

| Flag | Output |
|---|---|
| `--print` | Summary table to console |
| `--csv` | `<asset_id>.csv` |
| `--json` | `<asset_id>.json` |
| `--pdf` | `<asset_id>.pdf` (US Letter, one finding per page) |
| `--markdown` | `<asset_id>.md` |

Flags can be combined. At least one is required.
