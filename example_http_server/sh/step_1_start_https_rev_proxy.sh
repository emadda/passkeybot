#!/usr/bin/env bash
set -euo pipefail


# Step 1: Start HTTPS reverse proxy tunnel.
# - This script will use the `cloudflared` CLI to set up a public https://$uuid.trycloudflare.com => localhost:7777 reverse proxy.
# - An HTTPS domain is needed to allow Passkey Related Origin Requests (ROR) to work.
# - `cloudflared` will generate a randomly generated public HTTPS domain that will last for the duration of the CLI. No sign in is required.
# - This script will extract that randomly generated HTTPS domain from the logs and write it to config.json.
# - Run the `step_2` script after.

# Set cwd to parent dir
d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$d/../"


# Write the new public HTTPS domain to config.json so the Bun web server can read it.
cfg="config.json"
tmp="config.json.tmp"
update_config() {
  d="$1"
  d="${d#https://}"   # strip protocol if present

  if [ -f "$cfg" ]; then
    jq --arg d "$d" '.your_domain = $d' "$cfg" > "$tmp"
  else
    jq -n --arg d "$d" '{your_domain:$d}' > "$tmp"
  fi

  mv "$tmp" "$cfg"
}

export -f update_config
export cfg tmp

# Start the tunnel and parse the public HTTPS it outputs to its logs.
# `--config /dev/null` = avoid reading an existing tunnel config file, which would ignore the `--url` arg.
# `--loglevel debug` to debug issues.
cloudflared tunnel --config /dev/null --url http://localhost:7777 2>&1 \
  | tee /dev/stderr \
  | bash -c '
      updated=0
      while IFS= read -r l; do
        if [[ $updated -eq 0 && "$l" =~ https://[^[:space:]]*\.trycloudflare\.com ]]; then
          u="${BASH_REMATCH[0]}"
          update_config "$u"
          updated=1   # mark as done, but keep reading to keep the pipe open
        fi
      done
    '

