# Defaults
server="nginx"
run="latest"

# Parse command line options
while getopts :ms:r: opt; do
    case "${opt}" in
        m) minimal=1;; # Set minimal flag if -m option is provided
        s) server=${OPTARG};; # Set server variable to the value provided with -s option
        r) run=${OPTARG};; # Set run variable to the value provided with -r option
    esac
done

# List of libraries to test
libs=("quic-go" "ngtcp2" "mvfst" "quiche" "kwik" "picoquic" "aioquic" "neqo" "msquic" "chrome" "xquic" "lsquic" "quinn" "s2n-quic" "go-x-net")

# Test type
test="handshake"

# Iterate over each library in the list
for l in "${libs[@]}"; do
    # Hide implementation names if minimal output is requested
    if [ -z "$minimal" ]; then
        printf "%-15s |  " $l
    fi

    # The only test available for chrome is http3
    if [ "$l" == "chrome" ]; then
        t="http3"
    else
        t=$test
    fi

    # Download trace file and get QUIC fingerprint using tshark
    curl --no-progress-meter -f --output - "https://interop.seemann.io/logs/${run}/${server}_$l/$t/sim/trace_node_left.pcap" | tshark -Y "quic_fingerprint.str" -T fields -e "quic_fingerprint.str" -r - | head -n 1
done
