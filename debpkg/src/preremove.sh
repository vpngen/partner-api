#!/bin/sh

remove() {
        printf "\033[32m Pre Remove of a normal remove\033[0m\n"

        printf "\033[32m Stop the service unit\033[0m\n"
        systemctl stop --force embassy_api.service ||:
        systemctl disable embassy_api.service  ||:
}

upgrade() {
    printf "\033[32m Pre Remove of an upgrade\033[0m\n"
}

echo "$@"

action="$1"

case "$action" in
  "0" | "remove")
    remove
    ;;
  "1" | "upgrade")
    upgrade
    ;;
  "failed-upgrade")
    upgrade
    ;;
  *)
    printf "\033[32m Alpine\033[0m"
    remove
    ;;
esac
