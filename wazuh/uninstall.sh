#!/usr/bin/env bash
# Destructive local agent removal. Sourceable for offline tests; never run on a manager.
set +x
set -euo pipefail

fail() { printf 'Error: %s\n' "$*" >&2; exit 1; }
assert_removal_root() {
  (( EUID == 0 )) || fail 'Run the removal command with sudo.'
}
dpkg_state() {
  dpkg-query -W -f='${db:Status-Status}' "$1" 2>/dev/null || true
}
assert_agent_only() {
  local root=$1 manager_state=''
  if command -v dpkg-query >/dev/null; then manager_state=$(dpkg_state wazuh-manager); fi
  if [[ -n $manager_state && $manager_state != not-installed && $manager_state != config-files ]] ||
     { command -v rpm >/dev/null && rpm -q wazuh-manager >/dev/null 2>&1; } ||
     [[ -d $root/api || -e $root/bin/wazuh-analysisd || -e $root/bin/wazuh-authd || -e $root/bin/ossec-analysisd ]] ||
     { [[ -f /etc/ossec-init.conf ]] && grep -Eq "^[[:space:]]*TYPE=['\"]?(server|manager)" /etc/ossec-init.conf; }; then
    fail 'This is a Wazuh manager/server. This agent removal helper will not run here.'
  fi
}
assert_agent_tree() {
  local root=$1 mounted mounts
  [[ -n $root && ${root##*/} == ossec && ! -L $root && $(readlink -m -- "$root") == "$root" ]] || fail "Refusing linked or unexpected agent directory: $root"
  command -v findmnt >/dev/null || fail 'findmnt (util-linux) is required to check for mounted data.'
  mounts=$(findmnt -rn -o TARGET) || fail 'Could not inspect mounted filesystems; removal stopped.'
  while IFS= read -r mounted; do
    [[ $mounted != "$root" && $mounted != "$root/"* ]] || fail "Unmount agent data before removal: $mounted"
  done <<< "$mounts"
}
confirm_removal() {
  local answer
  printf 'This permanently removes the local Wazuh agent, /var/ossec, configuration, logs, identity keys, saved backups, and its dedicated service account. No backup is made.\n'
  read -r -p 'Type REMOVE to delete the local Wazuh agent: ' answer </dev/tty
  [[ $answer == REMOVE ]]
}
stop_agent() {
  local root=$1
  if systemctl cat wazuh-agent.service >/dev/null 2>&1; then systemctl disable --now wazuh-agent.service; fi
  if [[ -x $root/bin/wazuh-control ]]; then "$root/bin/wazuh-control" stop; fi
}
remove_agent_links() {
  if [[ -d $1 ]]; then find "$1" -xdev -type l -delete; fi
}
remove_agent_tree() {
  assert_agent_tree "$1"
  # GNU rm never follows symlinks; also keep filesystem boundaries intact.
  rm -rf --one-file-system -- "$1"
}
remove_agent_artifacts() {
  rm -f -- /etc/init.d/wazuh-agent \
    /etc/systemd/system/wazuh-agent.service /usr/lib/systemd/system/wazuh-agent.service /lib/systemd/system/wazuh-agent.service \
    /etc/audit/plugins.d/af_wazuh.conf /etc/audisp/plugins.d/af_wazuh.conf
  # Do not recurse through a drop-in directory or another unit's symlink target.
  if [[ -d /etc/systemd/system/wazuh-agent.service.d && ! -L /etc/systemd/system/wazuh-agent.service.d ]]; then
    find /etc/systemd/system/wazuh-agent.service.d -mindepth 1 -maxdepth 1 \( -type f -o -type l \) -delete
    rmdir /etc/systemd/system/wazuh-agent.service.d
  elif [[ -L /etc/systemd/system/wazuh-agent.service.d ]]; then
    rm -f -- /etc/systemd/system/wazuh-agent.service.d
  fi
  find /etc/systemd/system -xdev -type l -name wazuh-agent.service -delete
  if [[ -f /etc/ossec-init.conf ]] && grep -Eq "^[[:space:]]*TYPE=['\"]?agent" /etc/ossec-init.conf; then rm -f -- /etc/ossec-init.conf; fi
  systemctl daemon-reload
  systemctl reset-failed wazuh-agent.service >/dev/null 2>&1 || true
}
remove_agent_account() {
  local entry account_uid account_home account_shell group_entry group_gid group_members
  if entry=$(getent passwd wazuh); then
    IFS=: read -r _ _ account_uid _ _ account_home account_shell <<< "$entry"
    [[ $account_uid != 0 && $account_home == /var/ossec && ( $account_shell == */nologin || $account_shell == */false ) ]] || fail 'The wazuh account is not a dedicated agent account; manual review is required.'
    userdel wazuh
  fi
  if group_entry=$(getent group wazuh); then
    IFS=: read -r _ _ group_gid group_members <<< "$group_entry"
    [[ $group_gid != 0 && -z $group_members ]] || fail 'The wazuh group still has members; manual review is required.'
    if getent passwd | awk -F: -v gid="$group_gid" '$4 == gid { found=1 } END { exit !found }'; then
      fail 'Another account uses the wazuh primary group; manual review is required.'
    fi
    groupdel wazuh
  fi
}
main() {
  if [[ ${1:-} == --help ]]; then
    printf 'Usage: sudo bash uninstall.sh\nPermanently remove a Debian/Ubuntu or RHEL/Fedora Wazuh agent and all its local data. Requires typing REMOVE. Never runs on a manager.\n'
    return
  fi
  (( $# == 0 )) || fail 'Usage: sudo bash uninstall.sh'
  assert_removal_root
  command -v systemctl >/dev/null || fail 'A systemd-based Linux installation is required.'
  local root=/var/ossec backend package_state='' rpm_manager=''
  assert_agent_only "$root"
  assert_agent_tree "$root"
  if command -v apt-get >/dev/null && command -v dpkg-query >/dev/null; then
    backend=deb
    package_state=$(dpkg_state wazuh-agent)
  elif command -v rpm >/dev/null && { command -v dnf >/dev/null || command -v yum >/dev/null; }; then
    backend=rpm
    rpm_manager=$(command -v dnf || command -v yum)
    if rpm -q wazuh-agent >/dev/null 2>&1; then package_state=installed; fi
  else
    fail 'Supported Linux families: Debian/Ubuntu and RHEL/Fedora derivatives.'
  fi
  if ! confirm_removal; then printf 'Cancelled. Nothing was removed.\n'; return; fi
  stop_agent "$root"
  remove_agent_links "$root"
  if [[ -n $package_state && $package_state != not-installed ]]; then
    if [[ $backend == deb ]]; then
      apt-get purge -y wazuh-agent
    else
      "$rpm_manager" --setopt=clean_requirements_on_remove=0 remove -y wazuh-agent
    fi
  fi
  # A package-manager failure stops here; do not erase data behind its back.
  if [[ $backend == deb ]]; then
    package_state=$(dpkg_state wazuh-agent)
    [[ -z $package_state || $package_state == not-installed ]] || fail 'The agent package is still registered; removal is incomplete.'
  else
    ! rpm -q wazuh-agent >/dev/null 2>&1 || fail 'The agent package is still registered; removal is incomplete.'
  fi
  # Also catch a package in another available database before deleting leftovers.
  if command -v rpm >/dev/null && rpm -q wazuh-agent >/dev/null 2>&1; then fail 'An RPM agent package is still registered; cleanup stopped.'; fi
  remove_agent_tree "$root"
  remove_agent_artifacts
  remove_agent_account
  printf 'Local Wazuh agent, data, and identity removed.\nHave the server owner remove the old manager registration before reusing this device name. Then run the installation command from https://shivanshu.ca/wazuh/.\n'
}
if [[ ${BASH_SOURCE[0]:-$0} == "$0" ]]; then main "$@"; fi
