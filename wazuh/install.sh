#!/usr/bin/env bash
# One-time agent installation. Never accepts passwords in arguments or URLs.
set +x
set -euo pipefail

base_url='https://shivanshu.ca/wazuh'
work_dir=''
auth_file=''
auth_created=0

fail() { printf 'Error: %s\n' "$*" >&2; exit 1; }
cleanup() {
  if (( auth_created )); then rm -f -- "$auth_file"; fi
  if [[ -n $work_dir ]]; then rm -rf -- "$work_dir"; fi
}
fetch_file() {
  [[ $1 == https://shivanshu.ca/wazuh/* || $1 == https://packages.wazuh.com/4.x/* ]] || fail 'Unexpected download origin.'
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 15 --max-time 300 "$1" -o "$2"
}
verify_hash() {
  local actual
  actual=$("sha${3}sum" "$1")
  actual=${actual%% *}
  [[ $actual == "$2" ]] || fail "SHA-$3 verification failed. Nothing will be executed from that download."
}
verify_certificate() {
  python3 - "$1" "$2" <<'PY'
import hashlib,re,ssl,sys
p=open(sys.argv[1]).read()
if not re.fullmatch(r'\s*-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*',p):
    raise SystemExit('Expected exactly one public certificate')
if hashlib.sha256(ssl.PEM_cert_to_DER_cert(p.strip())).hexdigest()!=sys.argv[2]:
    raise SystemExit('Enrollment certificate fingerprint mismatch')
PY
  openssl verify -CAfile "$1" -purpose sslserver -verify_hostname "$3" "$1"
  openssl x509 -in "$1" -noout -checkend 86400 >/dev/null || fail 'Enrollment certificate expires too soon.'
}
configure_agent() {
  python3 - "$1" "$2" "$3" <<'PY'
from pathlib import Path
import os
import sys
import tempfile
import xml.etree.ElementTree as ET
root, host, name = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
path = root / 'etc/ossec.conf'
info = path.stat()
wrapper = ET.fromstring('<root>' + path.read_text() + '</root>')
configs = wrapper.findall('ossec_config')
if not configs:
    raise SystemExit('Invalid official agent configuration')
client = configs[0].find('client')
if client is None:
    client = ET.SubElement(configs[0], 'client')
for entry in list(client):
    if entry.tag in ('server', 'enrollment'):
        client.remove(entry)
server = ET.SubElement(client, 'server')
for key, value in {'address':host, 'port':'1514', 'protocol':'tcp'}.items():
    ET.SubElement(server, key).text = value
# agent-auth performs the one-time password enrollment before service startup.
enrollment = ET.SubElement(client, 'enrollment')
ET.SubElement(enrollment, 'enabled').text = 'no'
for config in configs:
    for entry in config.findall('active-response'):
        config.remove(entry)
response = ET.SubElement(configs[0], 'active-response')
ET.SubElement(response, 'disabled').text = 'yes'
fd, temporary = tempfile.mkstemp(dir=path.parent)
try:
    with os.fdopen(fd, 'w') as output:
        output.write('\n'.join(ET.tostring(config, encoding='unicode') for config in wrapper))
    os.chown(temporary, info.st_uid, info.st_gid)
    os.chmod(temporary, info.st_mode & 0o777)
    os.replace(temporary, path)
finally:
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
options = root / 'etc/local_internal_options.conf'
keys = ('logcollector.remote_commands', 'wazuh_command.remote_commands', 'sca.remote_commands')
lines = options.read_text().splitlines() if options.exists() else []
lines = [line for line in lines if line.split('=',1)[0].strip() not in keys]
options.write_text('\n'.join(lines + [key+'=0' for key in keys]) + '\n')
PY
}
read_enrollment_password() {
  IFS= read -r -s -p 'Enrollment password (hidden): ' password </dev/tty || fail 'Password entry cancelled.'
  printf '\n' >/dev/tty
}
enroll_agent() {
  local root=$1 manager=$2 agent_name=$3
  local auth_fd password exit_code
  export -n password
  auth_file="$root/etc/authd.pass"
  while true; do
    [[ ! -s $root/etc/client.keys && ! -s $root/etc/client.keys.save ]] || fail 'An agent identity exists; enrollment stopped. Existing identities are never replaced.'
    set -o noclobber
    exec {auth_fd}> "$auth_file" || fail 'Enrollment password file already exists; it was not overwritten.'
    set +o noclobber
    auth_created=1
    # Also restrict inherited POSIX ACL masks before writing any secret.
    chmod 600 "$auth_file"
    read_enrollment_password
    [[ -n $password && ${#password} -le 1024 && $password != *$'\r'* ]] || fail 'Invalid enrollment password.'
    printf '%s\n' "$password" >&"$auth_fd"
    unset password
    exec {auth_fd}>&-
    exit_code=0
    # Truncate the log each time so an earlier password failure cannot trigger a retry.
    timeout 45 "$root/bin/agent-auth" -m "$manager" -A "$agent_name" -v "$root/etc/enrollment-manager.pem" >"$work_dir/enrollment.log" 2>&1 || exit_code=$?
    rm -f -- "$auth_file"
    auth_created=0
    if (( exit_code == 0 )); then
      [[ -s $root/etc/client.keys ]] || fail 'The manager did not issue an identity key.'
      return
    fi
    [[ ! -s $root/etc/client.keys && ! -s $root/etc/client.keys.save ]] || fail 'An agent identity exists after enrollment failed; preserve it and inspect the agent logs before retrying.'
    # Wazuh 4.14 reports password rejection explicitly; other failures need diagnosis.
    if (( exit_code == 1 )) && grep -Eq 'agent-auth: ERROR: Invalid password(\. Unable to add agent)? \(from manager\)[[:space:]]*$' "$work_dir/enrollment.log"; then
      printf 'Incorrect enrollment password. Please try again (Ctrl+C to cancel).\n'
      continue
    fi
    fail "Enrollment failed. The agent remains stopped; check $root/logs/ossec.log and the manager logs. Existing identities are never replaced."
  done
}
main() {
  if [[ ${1:-} == --help ]]; then
    printf 'Usage: sudo bash install.sh\nFresh Debian/Ubuntu or RHEL-compatible installation only.\n'
    return
  fi
  (( $# == 0 )) || fail 'Usage: sudo bash install.sh'
  unset WAZUH_MANAGER WAZUH_REGISTRATION_SERVER WAZUH_REGISTRATION_PASSWORD WAZUH_REGISTRATION_CA WAZUH_AGENT_NAME WAZUH_AGENT_GROUP
  (( EUID == 0 )) || fail 'Run the installation command with sudo.'
  [[ -r /dev/tty ]] || fail 'An interactive terminal is required.'
  [[ ! -e /var/ossec ]] || fail 'An agent/manager directory already exists. Existing installations are not replaced.'
  command -v systemctl >/dev/null || fail 'A systemd-based Linux installation is required.'
  local distro package_key architecture
  # The target endpoint supplies its own standard os-release file.
  # shellcheck disable=SC1091
  distro=$( . /etc/os-release; printf '%s %s' "$ID" "${ID_LIKE:-}" )
  case " $distro " in
    *debian*|*ubuntu*) package_key='deb'; command -v apt-get >/dev/null || fail 'apt-get is required.' ;;
    *rhel*|*fedora*|*centos*|*rocky*|*almalinux*|*amzn*|*' ol '*) package_key='rpm'; command -v dnf >/dev/null || command -v yum >/dev/null || fail 'dnf or yum is required.' ;;
    *) fail 'Supported Linux families: Debian/Ubuntu and RHEL/Fedora derivatives.' ;;
  esac
  if [[ $package_key == deb ]]; then
    if dpkg-query -W -f='${Status}' wazuh-agent 2>/dev/null | grep -qx 'install ok installed'; then fail 'A Wazuh agent package is already installed.'; fi
  elif rpm -q wazuh-agent >/dev/null 2>&1; then
    fail 'A Wazuh agent package is already installed.'
  fi
  case $(uname -m) in x86_64|amd64) architecture=amd64 ;; aarch64|arm64) architecture=arm64 ;; *) fail 'Supported CPU architectures: x86-64 and ARM64.' ;; esac
  printf 'This installs the official Wazuh agent and any missing curl/OpenSSL/Python utilities.\n'
  local answer
  read -r -p 'Continue? [y/N] ' answer </dev/tty
  [[ $answer == [yY] || $answer == [yY][eE][sS] ]] || fail 'Cancelled.'
  if ! command -v python3 >/dev/null || ! command -v openssl >/dev/null || ! command -v curl >/dev/null; then
    if [[ $package_key == deb ]]; then
      apt-get update
      apt-get install -y ca-certificates curl openssl python3
    else
      local rpm_manager
      rpm_manager=$(command -v dnf || command -v yum)
      "$rpm_manager" install -y ca-certificates curl openssl python3
    fi
  fi
  python3 -c 'import sys; sys.exit(sys.version_info < (3, 6))' || fail 'Python 3.6 or newer is required.'
  command -v timeout >/dev/null || fail 'GNU timeout/coreutils is required.'
  umask 077
  work_dir=$(mktemp -d)
  trap cleanup EXIT
  fetch_file "$base_url/release.json" "$work_dir/release.json"
  local -a fields
  mapfile -t fields < <(python3 - "$work_dir/release.json" "${package_key}_${architecture}" <<'PY'
import json,re,sys
r=json.load(open(sys.argv[1])); p=r['packages'][sys.argv[2]]
kind,arch=sys.argv[2].split('_')
version=re.escape(r['agent_version'])
if kind=='deb':
    package_pattern=rf'https://packages\.wazuh\.com/4\.x/apt/pool/main/w/wazuh-agent/wazuh-agent_{version}-\d+_{arch}\.deb'
else:
    rpm_arch={'amd64':'x86_64','arm64':'aarch64'}[arch]
    package_pattern=rf'https://packages\.wazuh\.com/4\.x/yum/wazuh-agent-{version}-\d+\.{rpm_arch}\.rpm'
if not (r['schema']==1 and re.fullmatch(r'4\.\d+\.\d+',r['agent_version'])
        and re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?',r['manager'])
        and re.fullmatch(package_pattern,p['url'])
        and re.fullmatch(r'[a-f0-9]{128}',p['sha512'])
        and re.fullmatch(r'[a-f0-9]{64}',r['certificate_sha256'])):
    raise SystemExit('Invalid release metadata')
print(r['agent_version']);print(r['manager']);print(r['certificate_sha256']);print(p['url']);print(p['sha512'])
PY
  )
  [[ ${#fields[@]} == 5 ]] || fail 'Invalid release metadata.'
  local version=${fields[0]} manager=${fields[1]} certificate_hash=${fields[2]} package_url=${fields[3]} package_hash=${fields[4]}
  fetch_file "$base_url/certificate.pem" "$work_dir/certificate.pem"
  verify_certificate "$work_dir/certificate.pem" "$certificate_hash" "$manager"
  python3 - "$manager" <<'PY'
import socket,sys
for port in (1514,1515):
    with socket.create_connection((sys.argv[1],port),timeout=8): pass
PY
  printf 'Manager: %s\nAgent version: %s\n' "$manager" "$version"
  local agent_name
  read -r -p "Agent name [$(hostname -s)]: " agent_name </dev/tty
  agent_name=${agent_name:-$(hostname -s)}
  [[ $agent_name =~ ^[a-zA-Z0-9_.-]{2,128}$ ]] || fail 'Agent names need 2-128 letters, digits, dots, underscores, or hyphens.'
  fetch_file "$package_url" "$work_dir/agent.$package_key"
  verify_hash "$work_dir/agent.$package_key" "$package_hash" 512
  if [[ $package_key == deb ]]; then
    apt-get install -y "$work_dir/agent.deb"
  else
    local rpm_manager
    rpm_manager=$(command -v dnf || command -v yum)
    "$rpm_manager" install -y "$work_dir/agent.rpm"
  fi
  systemctl stop wazuh-agent
  systemctl disable wazuh-agent
  [[ -x /var/ossec/bin/agent-auth && ! -s /var/ossec/etc/client.keys ]] || fail 'Existing agent identity or unexpected package layout; enrollment stopped.'
  install -m 644 "$work_dir/certificate.pem" /var/ossec/etc/enrollment-manager.pem
  configure_agent /var/ossec "$manager" "$agent_name"
  enroll_agent /var/ossec "$manager" "$agent_name"
  systemctl daemon-reload
  systemctl enable --now wazuh-agent
  systemctl is-active --quiet wazuh-agent || fail 'Agent service did not start.'
  printf 'Agent installed and enrolled. Confirm %s is Active in the Wazuh dashboard.\n' "$agent_name"
}
if [[ ${BASH_SOURCE[0]:-$0} == "$0" ]]; then main "$@"; fi
