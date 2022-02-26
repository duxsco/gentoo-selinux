#!/usr/bin/env bash

DMESG_DENIALS="$(dmesg | grep "^\[.*\][[:space:]]*audit:[[:space:]]*.*[[:space:]]*avc:[[:space:]]*denied[[:space:]]")"

if [[ -z ${DMESG_DENIALS} ]]; then
    echo "No denials found in dmesg. Aborting..." >&2
    exit 0
fi

DMESG_CONTEXT="$(dmesg | grep -Po "^\[.*\][[:space:]]*audit:[[:space:]]*.*[[:space:]]*avc:[[:space:]]*denied[[:space:]]*.*\Kscontext=[^[:space:]]*[[:space:]]*tcontext=[^[:space:]]*" | uniq)"

if [[ $(wc -l <<<"${DMESG_CONTEXT}") -ge 2 ]]; then
    DMESG_DENIALS_RELEVANT="$(grep -m 1 -B 999 "$(sed '2q;d' <<<"${DMESG_CONTEXT}")" <<<"${DMESG_DENIALS}" | sed '$d')"
else
    DMESG_DENIALS_RELEVANT="${DMESG_DENIALS}"
fi

AUDIT2ALLOW="$(audit2allow <<<"${DMESG_DENIALS_RELEVANT}")"

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

if grep -q -E "^mydmesg_[0-9]{5}-" < <(semodule -l); then
    INDEX="$(printf "%05d" "$(( $(semodule -l | grep -Po "^mydmesg_\K[0-9]{5}" | sort | tail -n 1 | sed -e 's/^0*\([1-9]*\)/\1/' -e 's/^$/0/') + 1 ))")"
else
    INDEX="00000"
fi

OUTPUT="mydmesg_${INDEX}-${SELINUX_TYPE[0]}-${SELINUX_TYPE[1]}"

cat <<EOF > "${OUTPUT}.te" 
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
