#!/bin/sh
# SafetyWebbing container entrypoint: egress firewall, then drop to the agent user.
#
# The scan agent has FULL_ACCESS and reads untrusted web content, so it must be assumed
# prompt-injectable. Policing its network from OUTSIDE the container is not possible with
# `docker run` alone (it would reach the LAN, cloud metadata, this app's own API, ...), so
# the policy is installed here, as root, BEFORE the agent exists. The agent then runs as an
# unprivileged user with an empty capability set, so it cannot edit these rules.
#
# Policy (default deny, OUTBOUND):
#   - loopback and replies to connections already open
#   - DNS to the resolvers in /etc/resolv.conf
#   - TCP to host.docker.internal ONLY on the scan target's port
#   - TCP/443 to the IPs of the allowed API hosts (resolved once, now)
#   - everything else is rejected, IPv6 included
#
# The engine (src/safetywebbing/engines/live.py) sets SAFETYWEBBING_FIREWALL=1 and passes
# the port / hosts. Without it (a hand-run `docker run` smoke test) there is NO firewall.
# Needs: --cap-add NET_ADMIN SETUID SETGID SETPCAP (the engine passes them).
#
# KEEP IN SYNC: agent_image/ and agent_image_hackingbuddy/ carry identical copies
# (tests/test_entrypoint.py enforces it).

set -eu

AGENT_BIN="${SAFETYWEBBING_AGENT_BIN:?SAFETYWEBBING_AGENT_BIN not set (see Dockerfile)}"
AGENT_USER=agent

log() { echo "[sw-entrypoint] $*" >&2; }
die() { log "FATAL: $*"; exit 97; }

# Run the agent as the unprivileged user with NO capabilities and no way to gain any.
drop_and_exec() {
    exec setpriv --reuid="$AGENT_USER" --regid="$AGENT_USER" --init-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
        -- "$AGENT_BIN" "$@"
}

if [ "${SAFETYWEBBING_FIREWALL:-0}" != "1" ]; then
    log "WARNING: SAFETYWEBBING_FIREWALL is not set - running WITHOUT an egress firewall."
    drop_and_exec "$@"
fi

# --- validate the policy inputs (they come from the host app, but this runs as root) ---
PORT="${SAFETYWEBBING_TARGET_PORT:-}"
case "$PORT" in ''|*[!0-9]*) die "SAFETYWEBBING_TARGET_PORT must be a number, got '$PORT'" ;; esac
[ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die "target port out of range: $PORT"

DOMAINS="$(echo "${SAFETYWEBBING_ALLOW_DOMAINS:-}" | tr ',' ' ')"
for d in $DOMAINS; do
    case "$d" in
        *[!a-z0-9.-]*|.*|*.|*..*|-*) die "bad allowed domain '$d'" ;;
        *.*) ;;
        *) die "bad allowed domain '$d'" ;;
    esac
done

GATEWAY="$(getent ahostsv4 host.docker.internal | awk 'NR==1 {print $1}')"
[ -n "$GATEWAY" ] || die "cannot resolve host.docker.internal (is --add-host set?)"

ipt() { iptables "$@" || die "iptables $*"; }

# --- IPv4 ---
ipt -F INPUT; ipt -F OUTPUT; ipt -F FORWARD
ipt -P INPUT DROP; ipt -P FORWARD DROP; ipt -P OUTPUT DROP
ipt -A INPUT -i lo -j ACCEPT
ipt -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
ipt -A OUTPUT -o lo -j ACCEPT
ipt -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

for ns in $(awk '/^nameserver/ && $2 !~ /:/ {print $2}' /etc/resolv.conf); do
    ipt -A OUTPUT -p udp -d "$ns" --dport 53 -j ACCEPT
    ipt -A OUTPUT -p tcp -d "$ns" --dport 53 -j ACCEPT
done

ipt -A OUTPUT -p tcp -d "$GATEWAY" --dport "$PORT" -j ACCEPT

resolved=0
for d in $DOMAINS; do
    ips="$(getent ahostsv4 "$d" | awk '{print $1}' | sort -u)"
    if [ -z "$ips" ]; then
        log "warning: allowed domain '$d' did not resolve"
        continue
    fi
    for ip in $ips; do
        ipt -A OUTPUT -p tcp -d "$ip" --dport 443 -j ACCEPT
        resolved=$((resolved + 1))
    done
done
if [ -n "$DOMAINS" ] && [ "$resolved" -eq 0 ]; then
    die "none of the allowed domains resolved - the agent could not reach its LLM"
fi

ipt -A OUTPUT -j REJECT --reject-with icmp-port-unreachable
ipt -A INPUT -j DROP

# --- IPv6: allow nothing but loopback ---
if ip6tables -F INPUT 2>/dev/null && ip6tables -F OUTPUT && ip6tables -F FORWARD \
    && ip6tables -P INPUT DROP && ip6tables -P FORWARD DROP && ip6tables -P OUTPUT DROP \
    && ip6tables -A INPUT -i lo -j ACCEPT && ip6tables -A OUTPUT -o lo -j ACCEPT; then
    :
elif grep -qv ' lo$' /proc/net/if_inet6 2>/dev/null; then
    die "IPv6 is enabled but ip6tables could not lock it down"
else
    log "IPv6 not enabled in this container; nothing to lock down"
fi

# --- prove the policy works before trusting it: these must NOT be reachable ---
reachable() { timeout 5 curl -s -o /dev/null --max-time 3 "$1" >/dev/null 2>&1; }
other_port=8000
[ "$PORT" = "$other_port" ] && other_port=8001
for url in "http://1.1.1.1/" "http://169.254.169.254/" "http://$GATEWAY:$other_port/"; do
    if reachable "$url"; then
        die "egress check failed: $url is reachable although it must be blocked"
    fi
done

log "egress firewall active: target port $PORT on host, hosts: ${DOMAINS:-none}"
drop_and_exec "$@"
