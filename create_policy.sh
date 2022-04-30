#!/usr/bin/env bash

if grep -q -E "^\[.*\][[:space:]]+audit:[[:space:]]+type=1404[[:space:]]+.*[[:space:]]+enforcing=1[[:space:]]+" < <(dmesg); then
	SELINUX_MODE="enforcing"
else
	SELINUX_MODE="permissive"
fi

#######
# log #
#######

DMESG_DENIALS="$(dmesg | grep -E "^\[.*\][[:space:]]+audit:[[:space:]]+.*[[:space:]]+avc:[[:space:]]+denied[[:space:]]")"
AUSEARCH_DENIALS="$(ausearch --message avc --start boot)"

if [[ -n ${DMESG_DENIALS} ]]; then
    DMESG_CONTEXT="$(dmesg | grep -Po "^\[.*\][[:space:]]+audit:[[:space:]]+.*[[:space:]]+avc:[[:space:]]+denied[[:space:]]+.*\Kscontext=[^[:space:]]+[[:space:]]+tcontext=[^[:space:]]+" | uniq)"

    if [[ $(wc -l <<<"${DMESG_CONTEXT}") -ge 2 ]]; then
        DENIALS_RELEVANT="$(grep -m 1 -B 999 "$(sed '2q;d' <<<"${DMESG_CONTEXT}")" <<<"${DMESG_DENIALS}" | sed '$d')"
    else
        DENIALS_RELEVANT="${DMESG_DENIALS}"
    fi

    LOG_SOURCE="dmesg"
elif [[ -n ${AUSEARCH_DENIALS} ]]; then
    AUSEARCH_CONTEXT="$(ausearch --message avc --start boot | grep -Po "^type=AVC[[:space:]]+msg=audit(.*):[    [:space:]]+avc:[[:space:]]+denied[[:space:]]+{.*}.*\Kscontext=[^[:space:]]+[[:space:]]+tcontext=[^[:space:] ]+" | uniq)"

    if [[ $(wc -l <<<"${AUSEARCH_CONTEXT}") -ge 2 ]]; then
        DENIALS_RELEVANT="$(grep -m 1 -B 999 "$(sed '2q;d' <<<"${AUSEARCH_CONTEXT}")" <<<"${AUSEARCH_DENIALS}" | grep -B 999 "$(head -n 1 <<<"${AUSEARCH_CONTEXT}")")"
    else
        DENIALS_RELEVANT="${AUSEARCH_DENIALS}"
    fi

    LOG_SOURCE="ausearch"
else
    echo "No denials found. Aborting..." >&2
    exit 0
fi

#######
# meh #
#######

AUDIT2ALLOW="$(audit2allow <<<"${DENIALS_RELEVANT}")"

if grep -q '#!!!!' <<<"${AUDIT2ALLOW}"; then
cat <<EOF >&2
audit2allow printed a warning:
${AUDIT2ALLOW}

Aborting...
EOF
    exit 1
fi

AUDIT2ALLOW_ALLOW="$(grep "^allow[[:space:]]" <<<"${AUDIT2ALLOW}")"
readarray -t SELINUX_TYPE < <(cut -d ':' -f1 <<<"${AUDIT2ALLOW_ALLOW}" | awk '{print $2" "$3}' | xargs | tr ' ' '\n')

if grep -q -E "^my_[0-9]{5}_" < <(semodule -l); then
    INDEX="$(printf "%05d" "$(( $(semodule -l | grep -Po "^my_\K[0-9]{5}" | sort | tail -n 1 | sed -e 's/^0*\([1-9]*\)/\1/' -e 's/^$/0/') + 1 ))")"
else
    INDEX="00000"
fi

OUTPUT="my_${INDEX}_${SELINUX_MODE}_${LOG_SOURCE}-${SELINUX_TYPE[0]}-${SELINUX_TYPE[1]}"

# shellcheck disable=SC2001
cat <<EOF > "${OUTPUT}.te"
$(sed 's/^/#/' <<<"${DENIALS_RELEVANT}")

policy_module(${OUTPUT}, 1.0)

gen_require(\`
$(printf '  type %s;\n' "${SELINUX_TYPE[@]}" | sort -u | grep -v "^  type self;$")
')

${AUDIT2ALLOW_ALLOW}
EOF

cat <<EOF
"${OUTPUT}.te" has been created!

Please, check the file, create the policy module and install it:
make -f /usr/share/selinux/strict/include/Makefile ${OUTPUT}.pp
semodule -i ${OUTPUT}.pp
EOF
