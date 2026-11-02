# Deploy templates (least privilege)

Copy and edit paths. Units ship **without** `--allow-private-*`. Key sync never reloads nginx; lists reload is operator-driven after `nginx -t`.

| File | Role |
|---|---|
| `wba-keysync.service` + `.timer` | Fetch directories → key store (`User=wba`) |
| `wba-lists.service` + `.timer` | Fetch IP lists with `--write` (hourly); no reload |
| `wba-keysync.cron` | Same as keysync timer, cron form |

Day-2: `bun wba-keysync/wba-ops.ts` and `lua/wba/DAY-2.md`.
