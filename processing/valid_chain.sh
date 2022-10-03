# Get domain and version pairs
# Deduplicate (some domains might be in the input file twice, so also in the output)
# Remove 'null' entries, i.e., where the TLS connection failed.
versions=`cat "$1" | jq '[.[] | {"domain" : .domain, "chain": .tls_connection_info.valid_certificate_chain}] | unique | .[].chain' | grep -v "null"`

# number of lines
total=`echo "$versions" | wc --lines`

echo Total amount: $total

# use sed to create a field separator for awk.
echo "$versions" | sort -n | uniq -c | sort -rn | sed -E 's/[ \t]*([0-9]+)[ ]/\1:/' | awk -v tot=$total 'BEGIN {FS=":"; OFS="\t"; printf("%50s | %5s | %s\n", "Validity", "Count", "%X")} {printf("%50s | %5s | %.3f\n", $2, $1, ($1/tot))}'



