# Steps:
# 1. Deduplicate domains with the same cert_chain, does not have to be valid.
# 2. select the logs from each entry
# 3. Count the logs for each ID
# 4. OPTIONAL: Manually get the name of the log.

certs=$(cat "$1" | jq '[.[] | { "domain" : .domain, "chain" : .tls_connection_info.cert_chain.chain }] | unique | .[] |  .chain[0].text')

# this truncates the log ID to about 60% of it. We take the chance that there is a root ID with the first 60% the same
log_count=$(echo -e $certs| grep "Log ID " | wc --lines)
echo -e $certs | grep  "Log ID " | sort -n | uniq -c | sort -rn  | sed -E 's/[ \t]*([0-9]+)[ ]/\1=/' | awk -v tot=$log_count 'BEGIN {FS="="; OFS="\t"; printf("%50s | %5s | %s\n", "Log ID", "Count", "%X")} {printf("%50s | %5s | %.3f\n", $2, $1, ($1/tot))}'

echo Total amount of logs: $log_count
