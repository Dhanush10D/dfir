#!/bin/sh
# Inert demo copy of /tmp/.x.sh from web01: every line only prints text.
echo "powershell.exe -NoProfile -WindowStyle Hidden -enc RwBlAHQALQBQAHIAbwBjAGUAcwBzACAAfAAgAFMAZQBsAGUAYwB0AC0ATwBiAGoAZQBjAHQAIAAtAEYAaQByAHMAdAAgADUA"
echo "next stage: http://cdn-update.example/stage2"
echo "(crontab -l; echo '*/10 * * * * /tmp/.x.sh') | crontab -"
