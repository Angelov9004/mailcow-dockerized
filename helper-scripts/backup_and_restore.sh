#!/usr/bin/env bash

DEBIAN_DOCKER_IMAGE="ghcr.io/mailcow/backup:latest"

if [[ ! -z ${MAILCOW_BACKUP_LOCATION} ]]; then
  BACKUP_LOCATION="${MAILCOW_BACKUP_LOCATION}"
fi

if [[ ! ${1} =~ (backup|restore) ]]; then
  echo "First parameter needs to be 'backup' or 'restore'"
  exit 1
fi

if [[ ${1} == "backup" && ! ${2} =~ (crypt|vmail|redis|rspamd|postfix|mysql|postgres|all|--delete-days) ]]; then
  echo "Second parameter needs to be 'vmail', 'crypt', 'redis', 'rspamd', 'postfix', 'postgres', 'all' or '--delete-days'"
  exit 1
fi

if [[ -z ${BACKUP_LOCATION} ]]; then
  while [[ -z ${BACKUP_LOCATION} ]]; do
    read -ep "Backup location (absolute path, starting with /): " BACKUP_LOCATION
  done
fi

if [[ ! ${BACKUP_LOCATION} =~ ^/ ]]; then
  echo "Backup directory needs to be given as absolute path (starting with /)."
  exit 1
fi

if [[ -f ${BACKUP_LOCATION} ]]; then
  echo "${BACKUP_LOCATION} is a file!"
  exit 1
fi

if [[ ! -d ${BACKUP_LOCATION} ]]; then
  echo "${BACKUP_LOCATION} is not a directory"
  read -p "Create it now? [y|N] " CREATE_BACKUP_LOCATION
  if [[ ! ${CREATE_BACKUP_LOCATION,,} =~ ^(yes|y)$ ]]; then
    exit 1
  else
    mkdir -p ${BACKUP_LOCATION}
    chmod 755 ${BACKUP_LOCATION}
  fi
else
  if [[ ${1} == "backup" ]] && [[ -z $(echo $(stat -Lc %a ${BACKUP_LOCATION}) | grep -oE '[0-9][0-9][5-7]') ]]; then
    echo "${BACKUP_LOCATION} is not write-able for others, that's required for a backup."
    exit 1
  fi
fi

BACKUP_LOCATION=$(echo ${BACKUP_LOCATION} | sed 's#/$##')
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
COMPOSE_FILE=${SCRIPT_DIR}/../docker-compose.yml
ENV_FILE=${SCRIPT_DIR}/../.env
THREADS=$(echo ${THREADS:-1})
ARCH=$(uname -m)

if ! [[ "${THREADS}" =~ ^[1-9][0-9]?$ ]] ; then
  echo "Thread input is not a number!"
  exit 1
elif [[ "${THREADS}" =~ ^[1-9][0-9]?$ ]] ; then
  echo "Using ${THREADS} Thread(s) for this run."
  echo "Notice: You can set the Thread count with the THREADS Variable before you run this script."
fi

if [ ! -f ${COMPOSE_FILE} ]; then
  echo "Compose file not found"
  exit 1
fi

if [ ! -f ${ENV_FILE} ]; then
  echo "Environment file not found"
  exit 1
fi

echo "Using ${BACKUP_LOCATION} as backup/restore location."
echo

source ${SCRIPT_DIR}/../mailcow.conf

if [[ -z ${COMPOSE_PROJECT_NAME} ]]; then
  echo "Could not determine compose project name"
  exit 1
else
  echo "Found project name ${COMPOSE_PROJECT_NAME}"
  CMPS_PRJ=$(echo ${COMPOSE_PROJECT_NAME} | tr -cd "[0-9A-Za-z-_]")
fi

if grep --help 2>&1 | head -n 1 | grep -q -i "busybox"; then
  >&2 echo -e "\e[31mBusyBox grep detected on local system, please install GNU grep\e[0m"
  exit 1
fi


function backup() {
  DATE=$(date +"%Y-%m-%d-%H-%M-%S")
  mkdir -p "${BACKUP_LOCATION}/mailcow-${DATE}"
  chmod 755 "${BACKUP_LOCATION}/mailcow-${DATE}"
  cp "${SCRIPT_DIR}/../mailcow.conf" "${BACKUP_LOCATION}/mailcow-${DATE}"
  touch "${BACKUP_LOCATION}/mailcow-${DATE}/.$ARCH"
  for bin in docker; do
  if [[ -z $(which ${bin}) ]]; then
    >&2 echo -e "\e[31mCannot find ${bin} in local PATH, exiting...\e[0m"
    exit 1
  fi
  done
  while (( "$#" )); do
    case "$1" in
    vmail|all)
      docker run --name mailcow-backup --rm \
        -v ${BACKUP_LOCATION}/mailcow-${DATE}:/backup:z \
        -v $(docker volume ls -qf name=^${CMPS_PRJ}_vmail-vol-1$):/vmail:ro,z \
        ${DEBIAN_DOCKER_IMAGE} /bin/tar --warning='no-file-ignored' --use-compress-program="pigz --rsyncable -p ${THREADS}" -Pcvpf /backup/backup_vmail.tar.gz /vmail
      ;;&
    crypt|all)
      docker run --name mailcow-backup --rm \
        -v ${BACKUP_LOCATION}/mailcow-${DATE}:/backup:z \
        -v $(docker volume ls -qf name=^${CMPS_PRJ}_crypt-vol-1$):/crypt:ro,z \
        ${DEBIAN_DOCKER_IMAGE} /bin/tar --warning='no-file-ignored' --use-compress-program="pigz --rsyncable -p ${THREADS}" -Pcvpf /backup/backup_crypt.tar.gz /crypt
      ;;&
    redis|all)
      docker exec $(docker ps -qf name=redis-mailcow) redis-cli -a ${REDISPASS} --no-auth-warning save
      docker run --name mailcow-backup --rm \
        -v ${BACKUP_LOCATION}/mailcow-${DATE}:/backup:z \
        -v $(docker volume ls -qf name=^${CMPS_PRJ}_redis-vol-1$):/redis:ro,z \
        ${DEBIAN_DOCKER_IMAGE} /bin/tar --warning='no-file-ignored' --use-compress-program="pigz --rsyncable -p ${THREADS}" -Pcvpf /backup/backup_redis.tar.gz /redis
      ;;&
    rspamd|all)
      docker run --name mailcow-backup --rm \
        -v ${BACKUP_LOCATION}/mailcow-${DATE}:/backup:z \
        -v $(docker volume ls -qf name=^${CMPS_PRJ}_rspamd-vol-1$):/rspamd:ro,z \
        ${DEBIAN_DOCKER_IMAGE} /bin/tar --warning='no-file-ignored' --use-compress-program="pigz --rsyncable -p ${THREADS}" -Pcvpf /backup/backup_rspamd.tar.gz /rspamd
      ;;&
    postfix|all)
      docker run --name mailcow-backup --rm \
        -v ${BACKUP_LOCATION}/mailcow-${DATE}:/backup:z \
        -v $(docker volume ls -qf name=^${CMPS_PRJ}_postfix-vol-1$):/postfix:ro,z \
        ${DEBIAN_DOCKER_IMAGE} /bin/tar --warning='no-file-ignored' --use-compress-program="pigz --rsyncable -p ${THREADS}" -Pcvpf /backup/backup_postfix.tar.gz /postfix
      ;;&
    mysql|postgres|all)
      SQLIMAGE=$(grep -iEo 'postgres\:.+' ${COMPOSE_FILE} | head -n1)
      if [[ -z "${SQLIMAGE}" ]]; then
        echo "Could not determine SQL image version, skipping backup..."
        shift
        continue
      else
        echo "Using SQL image ${SQLIMAGE}, starting..."
        # logical dump (pg_dump custom format) - consistent snapshot, restorable into any newer PostgreSQL
        docker run --name mailcow-backup --rm \
          --network $(docker network ls -qf name=^${CMPS_PRJ}_mailcow-network$) \
          -e PGPASSWORD="${DBPASS}" \
          -v ${BACKUP_LOCATION}/mailcow-${DATE}:/backup:z \
          --entrypoint= \
          ${SQLIMAGE} /bin/sh -c "pg_dump -h postgres -U ${DBUSER} -d ${DBNAME} -Fc -f /backup/backup_postgres.dump && chmod 600 /backup/backup_postgres.dump"
      fi
      ;;&
    --delete-days)
      shift
      if [[ "${1}" =~ ^[0-9]+$ ]]; then
        find ${BACKUP_LOCATION}/mailcow-* -maxdepth 0 -mmin +$((${1}*60*24)) -exec rm -rvf {} \;
      else
        echo "Parameter of --delete-days is not a number."
      fi
      ;;
    esac
    shift
  done
}

function restore() {
  for bin in docker; do
  if [[ -z $(which ${bin}) ]]; then
    >&2 echo -e "\e[31mCannot find ${bin} in local PATH, exiting...\e[0m"
    exit 1
  fi
  done

  if [ "${DOCKER_COMPOSE_VERSION}" == "native" ]; then
  COMPOSE_COMMAND="docker compose"

  elif [ "${DOCKER_COMPOSE_VERSION}" == "standalone" ]; then
    COMPOSE_COMMAND="docker-compose"

  else
    echo -e "\e[31mCan not read DOCKER_COMPOSE_VERSION variable from mailcow.conf! Is your mailcow up to date? Exiting...\e[0m"
    exit 1
  fi

  echo
  echo "Stopping watchdog-mailcow..."
  docker stop $(docker ps -qf name=watchdog-mailcow)
  echo
  RESTORE_LOCATION="${1}"
  shift
  while (( "$#" )); do
    case "$1" in
    vmail)
      docker stop $(docker ps -qf name=dovecot-mailcow)
      docker run -i --name mailcow-backup --rm \
        -v ${RESTORE_LOCATION}:/backup:z \
        -v $(docker volume ls -qf name=^${CMPS_PRJ}_vmail-vol-1$):/vmail:z \
        ${DEBIAN_DOCKER_IMAGE} /bin/tar --use-compress-program="pigz -d -p ${THREADS}" -Pxvf /backup/backup_vmail.tar.gz
      docker start $(docker ps -aqf name=dovecot-mailcow)
      echo
      echo "In most cases it is not required to run a full resync, you can run the command printed below at any time after testing wether the restore process broke a mailbox:"
      echo
      echo "docker exec $(docker ps -qf name=dovecot-mailcow) doveadm force-resync -A '*'"
      echo
      read -p "Force a resync now? [y|N] " FORCE_RESYNC
      if [[ ${FORCE_RESYNC,,} =~ ^(yes|y)$ ]]; then
        docker exec $(docker ps -qf name=dovecot-mailcow) doveadm force-resync -A '*'
      else
        echo "OK, skipped."
      fi
      ;;
    redis)
      docker stop $(docker ps -qf name=redis-mailcow)
      docker run -i --name mailcow-backup --rm \
        -v ${RESTORE_LOCATION}:/backup:z \
        -v $(docker volume ls -qf name=^${CMPS_PRJ}_redis-vol-1$):/redis:z \
        ${DEBIAN_DOCKER_IMAGE} /bin/tar --use-compress-program="pigz -d -p ${THREADS}" -Pxvf /backup/backup_redis.tar.gz
      docker start $(docker ps -aqf name=redis-mailcow)
      ;;
    crypt)
      docker stop $(docker ps -qf name=dovecot-mailcow)
      docker run -i --name mailcow-backup --rm \
        -v ${RESTORE_LOCATION}:/backup:z \
        -v $(docker volume ls -qf name=^${CMPS_PRJ}_crypt-vol-1$):/crypt:z \
        ${DEBIAN_DOCKER_IMAGE} /bin/tar --use-compress-program="pigz -d -p ${THREADS}" -Pxvf /backup/backup_crypt.tar.gz
      docker start $(docker ps -aqf name=dovecot-mailcow)
      ;;
    rspamd)
      if [[ $(find "${RESTORE_LOCATION}" \( -name '*x86*' -o -name '*aarch*' \) -exec basename {} \; | sed 's/^\.//' | sed 's/^\.//') == "" ]]; then
        echo -e "\e[33mCould not find a architecture signature of the loaded backup... Maybe the backup was done before the multiarch update?"
        sleep 2
        echo -e "Continuing anyhow. If rspamd is crashing upon boot try remove the rspamd volume with docker volume rm ${CMPS_PRJ}_rspamd-vol-1 after you've stopped the stack.\e[0m"
        sleep 2
        docker stop $(docker ps -qf name=rspamd-mailcow)
        docker run -i --name mailcow-backup --rm \
          -v ${RESTORE_LOCATION}:/backup:z \
          -v $(docker volume ls -qf name=^${CMPS_PRJ}_rspamd-vol-1$):/rspamd:z \
          ${DEBIAN_DOCKER_IMAGE} /bin/tar --use-compress-program="pigz -d -p ${THREADS}" -Pxvf /backup/backup_rspamd.tar.gz
        docker start $(docker ps -aqf name=rspamd-mailcow)
      elif [[ $ARCH != $(find "${RESTORE_LOCATION}" \( -name '*x86*' -o -name '*aarch*' \) -exec basename {} \; | sed 's/^\.//' | sed 's/^\.//') ]]; then
        echo -e "\e[31mThe Architecture of the backed up mailcow OS is different then your restoring mailcow OS..."
        sleep 2
        echo -e "Skipping rspamd due to compatibility issues!\e[0m"
      else
        docker stop $(docker ps -qf name=rspamd-mailcow)
        docker run -i --name mailcow-backup --rm \
          -v ${RESTORE_LOCATION}:/backup:z \
          -v $(docker volume ls -qf name=^${CMPS_PRJ}_rspamd-vol-1$):/rspamd:z \
          ${DEBIAN_DOCKER_IMAGE} /bin/tar --use-compress-program="pigz -d -p ${THREADS}" -Pxvf /backup/backup_rspamd.tar.gz
        docker start $(docker ps -aqf name=rspamd-mailcow)
      fi
      ;;
    postfix)
      docker stop $(docker ps -qf name=postfix-mailcow)
      docker run -i --name mailcow-backup --rm \
        -v ${RESTORE_LOCATION}:/backup:z \
        -v $(docker volume ls -qf name=^${CMPS_PRJ}_postfix-vol-1$):/postfix:z \
        ${DEBIAN_DOCKER_IMAGE} /bin/tar --use-compress-program="pigz -d -p ${THREADS}" -Pxvf /backup/backup_postfix.tar.gz
      docker start $(docker ps -aqf name=postfix-mailcow)
      ;;
    mysql|mariadb|postgres)
      SQLIMAGE=$(grep -iEo 'postgres\:.+' ${COMPOSE_FILE} | head -n1)
      if [[ -z "${SQLIMAGE}" ]]; then
        echo "Could not determine SQL image version, skipping restore..."
        shift
        continue
      elif [ ! -f "${RESTORE_LOCATION}/mailcow.conf" ]; then
        echo "Could not find the corresponding mailcow.conf in ${RESTORE_LOCATION}, skipping restore."
        echo "If you lost that file, copy the last working mailcow.conf file to ${RESTORE_LOCATION} and restart the restore process."
        shift
        continue
      elif [ ! -f "${RESTORE_LOCATION}/backup_postgres.dump" ]; then
        echo "Could not find backup_postgres.dump in ${RESTORE_LOCATION}."
        echo "Backups of the former MariaDB stack must be migrated with helper-scripts/migrate-mysql-to-postgres.py instead."
        shift
        continue
      else
        read -p "mailcow will be stopped and the currently active mailcow.conf will be modified to use the DB parameters found in ${RESTORE_LOCATION}/mailcow.conf - do you want to proceed? [Y|n] " MYSQL_STOP_MAILCOW
        if [[ ${MYSQL_STOP_MAILCOW,,} =~ ^(no|n|N)$ ]]; then
          echo "OK, skipped."
          shift
          continue
        else
          echo "Stopping mailcow..."
          ${COMPOSE_COMMAND} -f ${COMPOSE_FILE} --env-file ${ENV_FILE} down
        fi
        echo "Modifying mailcow.conf..."
        source ${RESTORE_LOCATION}/mailcow.conf
        sed -i --follow-symlinks "/DBNAME/c\DBNAME=${DBNAME}" ${SCRIPT_DIR}/../mailcow.conf
        sed -i --follow-symlinks "/DBUSER/c\DBUSER=${DBUSER}" ${SCRIPT_DIR}/../mailcow.conf
        sed -i --follow-symlinks "/DBPASS/c\DBPASS=${DBPASS}" ${SCRIPT_DIR}/../mailcow.conf
        sed -i --follow-symlinks "/DBROOT/c\DBROOT=${DBROOT}" ${SCRIPT_DIR}/../mailcow.conf
        source ${SCRIPT_DIR}/../mailcow.conf
        echo "Starting database..."
        ${COMPOSE_COMMAND} -f ${COMPOSE_FILE} --env-file ${ENV_FILE} up -d postgres-mailcow
        until docker exec $(docker ps -qf name=postgres-mailcow) pg_isready -U ${DBUSER} -d ${DBNAME} -q; do sleep 2; done
        echo "Restoring..."
        docker run -i --name mailcow-backup --rm \
          --network $(docker network ls -qf name=^${CMPS_PRJ}_mailcow-network$) \
          -e PGPASSWORD="${DBPASS}" \
          -v ${RESTORE_LOCATION}:/backup:z \
          --entrypoint= \
          ${SQLIMAGE} /bin/sh -c "pg_restore -h postgres -U ${DBUSER} -d ${DBNAME} --clean --if-exists --no-owner --no-privileges /backup/backup_postgres.dump"
        echo "Starting mailcow..."
        ${COMPOSE_COMMAND} -f ${COMPOSE_FILE} --env-file ${ENV_FILE} up -d
      fi
      ;;
    esac
    shift
  done
  echo
  echo "Starting watchdog-mailcow..."
  docker start $(docker ps -aqf name=watchdog-mailcow)
}

if [[ ${1} == "backup" ]]; then
  backup ${@,,}
elif [[ ${1} == "restore" ]]; then
  i=1
  declare -A FOLDER_SELECTION
  if [[ $(find ${BACKUP_LOCATION}/mailcow-* -maxdepth 1 -type d 2> /dev/null| wc -l) -lt 1 ]]; then
    echo "Selected backup location has no subfolders"
    exit 1
  fi
  for folder in $(ls -d ${BACKUP_LOCATION}/mailcow-*/); do
    echo "[ ${i} ] - ${folder}"
    FOLDER_SELECTION[${i}]="${folder}"
    ((i++))
  done
  echo
  input_sel=0
  while [[ ${input_sel} -lt 1 ||  ${input_sel} -gt ${i} ]]; do
    read -p "Select a restore point: " input_sel
  done
  i=1
  echo
  declare -A FILE_SELECTION
  RESTORE_POINT="${FOLDER_SELECTION[${input_sel}]}"
  if [[ -z $(find "${FOLDER_SELECTION[${input_sel}]}" -maxdepth 1 \( -type d -o -type f \) -regex ".*\(redis\|rspamd\|postgres\|mariadb\|mysql\|crypt\|vmail\|postfix\).*") ]]; then
    echo "No datasets found"
    exit 1
  fi

  echo "[ 0 ] - all"
  # find all files in folder with *.gz extension, print their base names, remove backup_, remove .tar (if present), remove .gz
  FILE_SELECTION[0]=$(find "${FOLDER_SELECTION[${input_sel}]}" -maxdepth 1 \( -type d -o -type f \) \( -name '*.gz' -o -name '*.dump' -o -name 'mysql' \) -printf '%f\n' | sed 's/backup_*//' | sed 's/\.[^.]*$//' | sed 's/\.[^.]*$//')
  for file in $(ls -f "${FOLDER_SELECTION[${input_sel}]}"); do
    if [[ ${file} =~ vmail ]]; then
      echo "[ ${i} ] - Mail directory (/var/vmail)"
      FILE_SELECTION[${i}]="vmail"
      ((i++))
    elif [[ ${file} =~ crypt ]]; then
      echo "[ ${i} ] - Crypt data"
      FILE_SELECTION[${i}]="crypt"
      ((i++))
    elif [[ ${file} =~ redis ]]; then
      echo "[ ${i} ] - Redis DB"
      FILE_SELECTION[${i}]="redis"
      ((i++))
    elif [[ ${file} =~ rspamd ]]; then
      if [[ $(find "${FOLDER_SELECTION[${input_sel}]}" \( -name '*x86*' -o -name '*aarch*' \) -exec basename {} \; | sed 's/^\.//' | sed 's/^\.//') == "" ]]; then
        echo "[ ${i} ] - Rspamd data (unkown Arch detected, restore with caution!)"
        FILE_SELECTION[${i}]="rspamd"
        ((i++))
      elif [[ $ARCH != $(find "${FOLDER_SELECTION[${input_sel}]}" \( -name '*x86*' -o -name '*aarch*' \) -exec basename {} \; | sed 's/^\.//' | sed 's/^\.//') ]]; then
        echo -e "\e[31m[ NaN ] - Rspamd data (incompatible Arch, cannot restore it)\e[0m"
      else
        echo "[ ${i} ] - Rspamd data"
        FILE_SELECTION[${i}]="rspamd"
        ((i++))
      fi
    elif [[ ${file} =~ postfix ]]; then
      echo "[ ${i} ] - Postfix data"
      FILE_SELECTION[${i}]="postfix"
      ((i++))
    elif [[ ${file} =~ postgres ]] || [[ ${file} =~ mysql ]] || [[ ${file} =~ mariadb ]]; then
      echo "[ ${i} ] - SQL DB"
      FILE_SELECTION[${i}]="postgres"
      ((i++))
    fi
  done
  echo
  input_sel=-1
  while [[ ${input_sel} -lt 0 ||  ${input_sel} -gt ${i} ]]; do
    read -p "Select a dataset to restore: " input_sel
  done
  echo "Restoring ${FILE_SELECTION[${input_sel}]} from ${RESTORE_POINT}..."
  restore "${RESTORE_POINT}" ${FILE_SELECTION[${input_sel}]}
fi
