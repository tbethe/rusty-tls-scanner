# actions:
# Get domain and version pairs
# Deduplicate (some domains might be in the input file twice, so also in the output)
# Remove 'null' entries, i.e., where the TLS connection failed.
versions=`cat "$1" | jq '[.[] | {"domain" : .domain, "version": .tls_connection_info.tls_version}] | unique | .[].version' | grep -v "null"`

# number of lines
total=`echo "$versions" | wc --lines`

echo Total amount: $total

echo "$versions" | sort -n | uniq -c | sort -rn | awk -v tot=$total 'BEGIN {RS="\n"; OFS="\t"; printf("%10s | %5s | %s\n", "Version", "Count", "%X")} {printf("%10s | %5s | %.3f\n", $2, $1, ($1/tot))}'



