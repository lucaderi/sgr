#!/bin/bash
# demo_detection.sh - manual detector-module demo using test_detector
# Used in development only.
# Usage from src/defense/dhcp_starvation_detector:
#   sudo ./detector/demo_detection.sh [interface]   (default: ens160)

if [ -z "${BASH_VERSION:-}" ]; then
    exec bash "$0" "$@"
fi

IFACE="${1:-ens160}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MODULE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PROJECT_ROOT="$(cd "$MODULE_ROOT/../../.." && pwd)"
DETECTOR="$PROJECT_ROOT/bin/test_detector"
CONFIG="$MODULE_ROOT/config/config.yaml"
RRD="$MODULE_ROOT/db/dhcp_stats.rrd"
PNG="$MODULE_ROOT/dhcp.png"
LOG=$(mktemp /tmp/det_XXXXXX.log)

BASELINE_SECS="${BASELINE_SECS:-120}"   # seconds of normal traffic before the attack
POST_SECS="${POST_SECS:-$BASELINE_SECS}"
ATTACK_END_QUIET_LINES="${ATTACK_END_QUIET_LINES:-3}"
SHOW_LOG="${SHOW_LOG:-1}"
GRAPH_DISC_MAX="${GRAPH_DISC_MAX:-200}"

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; NC='\033[0m'
info() { echo -e "${GRN}[demo]${NC} $*"; }
warn() { echo -e "${YLW}[demo]${NC} $*"; }
err()  { echo -e "${RED}[demo]${NC} $*" >&2; }

DETECTOR_PID=""; TAIL_PID=""
stop_detector() {
    [ -n "$TAIL_PID"     ] && kill "$TAIL_PID"     2>/dev/null || true
    TAIL_PID=""

    [ -n "$DETECTOR_PID" ] && kill -INT "$DETECTOR_PID" 2>/dev/null || true
    [ -n "$DETECTOR_PID" ] && wait "$DETECTOR_PID" 2>/dev/null || true
    DETECTOR_PID=""
}

cleanup() {
    stop_detector
    rm -f "$LOG"
}
trap cleanup EXIT INT TERM

# -- prerequisites ------------------------------------------------------------
[ "$(id -u)" -ne 0 ]      && { err "Run as root: sudo $0 $IFACE"; exit 1; }
[ ! -x "$DETECTOR" ]      && { err "test_detector not found: build with make or make no-netconf"; exit 1; }
[ ! -r "$CONFIG" ]        && { err "config file not found: $CONFIG"; exit 1; }
command -v rrdtool  >/dev/null || { err "rrdtool missing: sudo apt install rrdtool"; exit 1; }
command -v dhcpcd   >/dev/null || { err "dhcpcd missing: sudo apt install dhcpcd"; exit 1; }

# -- send_discover: send a real DISCOVER/REQUEST through dhcpcd test mode -----
# -T = test mode: performs the full negotiation but does NOT apply the lease
#      (does not change the assigned IP and does not interfere with connectivity)
# -1 = exit after the first attempt
send_discover() {
    dhcpcd -T -1 --pidfile "/tmp/dhcpcd_demo_$$.pid" "$IFACE" >/dev/null 2>&1 || true
}

# -- baseline_traffic: legitimate DISCOVER packets every 3-8s for N seconds ---
baseline_traffic() {
    local end=$(( $(date +%s) + $1 ))
    while [ "$(date +%s)" -lt "$end" ]; do
        local step=$(( RANDOM % 6 + 3 ))          # random 3-8 seconds
        local rem=$(( end - $(date +%s) ))
        [ "$step" -gt "$rem" ] && step=$rem
        sleep "$step"
        [ "$(date +%s)" -lt "$end" ] && send_discover && \
            warn "  Legitimate DISCOVER sent (real interface MAC)"
    done
}

# ═══════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${GRN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GRN}║    DHCP Starvation Detection - Module demo       ║${NC}"
echo -e "${GRN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# -- 1. cleanup ----------------------------------------------------------------
DEMO_START=$(date +%s)
info "1/8  Removing previous RRD..."
rm -f "$RRD"

# -- 2. start detector ---------------------------------------------------------
info "2/8  Starting test_detector on $IFACE..."
stdbuf -oL "$DETECTOR" --config "$CONFIG" "$IFACE" > "$LOG" 2>&1 &
DETECTOR_PID=$!
sleep 2
grep -q "interface" "$LOG" 2>/dev/null || { err "Detector did not start"; exit 1; }
if [ "$SHOW_LOG" = "1" ]; then
    tail -f "$LOG" &
    TAIL_PID=$!
fi
info "    test_detector started (PID $DETECTOR_PID)"

# -- 3. pre-attack baseline ----------------------------------------------------
info "3/8  Pre-attack baseline (${BASELINE_SECS}s)..."
warn "    Legitimate DISCOVER packets every 3-8s - normal traffic running..."
baseline_traffic "$BASELINE_SECS"
info "    Pre-attack baseline completed."

# -- 4. ask the operator to start the attack ----------------------------------
info "4/8  Attack startup..."
echo ""
echo -e "${RED}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║   START the attack now from Kali (or another host):║${NC}"
echo -e "${RED}║                                                  ║${NC}"
echo -e "${RED}║   python3 dhcp_starvation_attack.py             ║${NC}"
echo -e "${RED}║     --count 200 --la on --no-wait <iface>       ║${NC}"
echo -e "${RED}╚══════════════════════════════════════════════════╝${NC}"
echo ""
warn "    Start the attack now: the demo keeps listening and continues automatically."

# -- 5. monitor attack detection and end --------------------------------------
info "5/8  Waiting for attack detection..."
TIMEOUT=600
t0=$(date +%s)
while ! grep -q "\*\*\* ATTACK \*\*\*" "$LOG" 2>/dev/null; do
    sleep 1
    if [ $(( $(date +%s) - t0 )) -gt $TIMEOUT ]; then
        err "Timeout: attack not detected after ${TIMEOUT}s"
        printf "  Continue anyway? [y/N] "
        read -r ans
        [ "$(printf '%s' "$ans" | tr '[:upper:]' '[:lower:]')" = "y" ] || exit 1
        break
    fi
done
echo ""
echo -e "${RED}[demo] *** ATTACK DETECTED - monitoring attack end... ***${NC}"

# Wait for the end: count new detector lines without *** ATTACK ***.
# Do not use tail -n 1: it is fragile if the last line is RRD or partial output.
quiet=0
last_line=$(wc -l < "$LOG" | tr -d ' ')
while [ "$quiet" -lt "$ATTACK_END_QUIET_LINES" ]; do
    sleep 1

    if ! kill -0 "$DETECTOR_PID" 2>/dev/null; then
        err "Detector stopped before the demo ended"
        exit 1
    fi

    total_lines=$(wc -l < "$LOG" | tr -d ' ')
    [ "$total_lines" -le "$last_line" ] && continue

    new_lines=$(sed -n "$(( last_line + 1 )),${total_lines}p" "$LOG")
    while IFS= read -r line; do
        case "$line" in
            "[detector]"*)
                case "$line" in
                    *"*** ATTACK ***"*) quiet=0 ;;
                    *) quiet=$(( quiet + 1 )) ;;
                esac
                ;;
        esac
    done <<EOF
$new_lines
EOF

    last_line=$total_lines
done
info "    Attack ended: detector stayed marker-free for ${ATTACK_END_QUIET_LINES} samples."

# -- 6. post-attack baseline ---------------------------------------------------
info "6/8  Post-attack baseline (${POST_SECS}s)..."
warn "    Legitimate DISCOVER packets every 3-8s - normal traffic restored..."
baseline_traffic "$POST_SECS"
info "    Post-attack baseline completed."

# -- 7. stop detector ----------------------------------------------------------
info "7/8  Stopping detector..."
stop_detector
info "    Detector stopped."

# -- 8. generate graph ---------------------------------------------------------
info "8/8  Generating graph $PNG..."
TOTAL_SECS=$(( $(date +%s) - DEMO_START + 30 ))
RIGHT_AXIS_SCALE=$(awk -v max="$GRAPH_DISC_MAX" 'BEGIN { printf "%.8f", 1 / max }')
rrdtool graph "$PNG" \
    --start="-${TOTAL_SECS}" --end=now \
    --title="DHCP Starvation Detection - traffic and baseline" \
    --vertical-label="window count" \
    --right-axis "$RIGHT_AXIS_SCALE:0" \
    --right-axis-label "la-ratio" \
    --right-axis-format "%4.2lf" \
    --lower-limit=0 --upper-limit="$GRAPH_DISC_MAX" --rigid \
    --width=900 --height=350 \
    "DEF:disc=$RRD:discovers:AVERAGE" \
    "DEF:disc_max=$RRD:discovers:MAX" \
    "DEF:unique=$RRD:unique_macs:MAX" \
    "DEF:baseline=$RRD:baseline_ema:AVERAGE" \
    "DEF:dev=$RRD:baseline_dev:AVERAGE" \
    "DEF:la=$RRD:la_ratio:MAX" \
    "CDEF:la_plot=la,${GRAPH_DISC_MAX},*" \
    "AREA:disc_max#FFCCCC:DISCOVER window max" \
    "LINE2:disc#CC0000:DISCOVER window avg" \
    "LINE2:unique#009900:unique MACs window" \
    "LINE1:baseline#0000CC:adaptive baseline" \
    "LINE1:dev#CC00CC:baseline deviation" \
    "LINE2:la_plot#FF9900:LA-bit ratio (right axis)"

echo ""
echo -e "${GRN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GRN}║  Demo completed. Graph saved to:                 ║${NC}"
echo -e "${GRN}║  $PNG  ${NC}"
echo -e "${GRN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
