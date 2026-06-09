# Demo GIFs

Terminal demos for the README, recorded with [VHS](https://github.com/charmbracelet/vhs).

## Regenerate

```bash
vhs docs/demo.tape
vhs docs/demo-audit.tape
```

## Files

| File | Purpose |
|------|---------|
| `demo.tape` / `demo.gif` | Download command demo |
| `demo-audit.tape` / `demo-audit.gif` | `--audit` security report demo |
| `demo-output.txt` | Curated download output |
| `demo-audit-output.txt` | Curated audit output |
| `record-demo-play.sh` | Replay script for download gif |
| `record-demo-audit-play.sh` | Replay script for audit gif |

To update after CLI changes, re-run real commands, refresh the `demo*-output.txt` files, then re-render both tapes.
