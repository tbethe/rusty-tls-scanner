#
# Domains can appear multiple times. If they have the same root certificate, 
# we want to deduplicate, otherwise they increase the count. 
# However, if they present different certificates, we do not want to deduplicate.
#
# The plan:
#
# 1. Get those where there is a valid cert. chain.
# 2. Let's create a list of domain/certificate_chain pairs , and then deduplicate.
# 3. Select the certificate_chain ROOTS
# 4. Count the root certificates
# 5. Manually match them with their organisation.

# 1 
certs=`cat "$1" | jq '[.[] | select(.tls_connection_info.valid_chain=="ok")]'`


# 2 + 3 + 4
total=$(echo $certs | jq 'length')
echo Total: $total
echo "$certs" | jq -c '[.[] | { "domain" : .domain, "chain" : .tls_connection_info.cert_chain.chain[-1].issuer_name }] | unique | .[] | .chain' | sort -n | uniq -c | sort -rn | sed -E 's/[ \t]*([0-9]+)[ ]/\1=/' | awk -v tot=$total 'BEGIN {FS="="; OFS="\t"; printf("%100s | %5s | %s\n", "CA", "Count", "%X")} {printf("%100s | %5s | %.3f\n", $2, $1, ($1/tot))}'

