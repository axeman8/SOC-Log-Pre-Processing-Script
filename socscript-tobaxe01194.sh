#!/bin/bash

##      Soc Log pre-processing script for CND

# Overview:
# This script automates daily SOC preprocessing on a web server:
#	- Validates input and secure transport (HTTPS)
#	- Fetches and integrity checks configuration and threat data (GPG)
#	- Collects apache logs and produces traffic/error analysis
#	- Performs local security checks (FS mount, firewall/ports, disk usage)
#	- Detects abuse patterns (excessive errors, high-risk paths, CTI IP matches)
#	- Packages, signs, checksums, uploads and verifies submission remotely

# Note:
#	- The lockfile is used to prevent concurrents runs
#	- Logging is written to /opt/security/logs/socscript.log
#	- The script is organized by tasks T1-T24 per the assignment


DEBUG=false

HOST=$(hostname)
TS=$(date +%Y%m%d-%H:%M)
FAIL_PREFIX="FAILED-${HOST} ${TS}:"


# T1 Ensure only one instance of the script runs at a time by creating lockfile

LOCKFILE=/var/run/socscript.$HOSTNAME.lock # Specifiying lockfile location

if [ -f $LOCKFILE ]; then
	echo "${FAIL_PREFIX} Lock file already exists, exiting."
	exit 1
fi

touch $LOCKFILE

trap "rm -f '$LOCKFILE'" EXIT # LOCKFILE is always removed on exit, even if it crashes

STARTDIR=$(pwd)

# Cleanup handler, removes lockfile and optionally working dir depending on value of "DEBUG"

cleanup() {
	echo "[$(date)] Cleaning up and restoring enviornment" >> "$LOGFILE"
	if [ -f "$LOCKFILE" ]; then
		rm -f "$LOCKFILE"
		echo "[$(date)] Removed lockfile: $LOCKFILE" >> "$LOGFILE"
	fi
	if [ "$DEBUG" = false ]; then
		if [ -d "$WORKDIR" ]; then
			rm -rf "$WORKDIR"
			echo "[$(date)] Removed working directory: $WORKDIR" >> "$LOGFILE"
		fi
	fi
	if [ -n "$STARTDIR" ]; then
		cd "$STARTDIR" 2>/dev/null || true
		echo "[$(date)] Returned to starting directory: $STARTDIR" >> "$LOGFILE"
	fi
	echo "[$(date)] Enviornment restored successfully" >> "$LOGFILE"
}
trap cleanup EXIT



# T2 Create dated working directory
DATE=$(date +%Y%m%d)
WORKDIR="/opt/security/tmp/socscript-$DATE"


if [ ! -d "$WORKDIR" ]; then # if working dir does not exit then create it
	mkdir -p "$WORKDIR"
fi

if [ ! -w "$WORKDIR" ]; then # Checks if working directory is writable, and throws error if not writable
	echo "${FAIL_PREFIX} $WORKDIR is not writable."
	exit 1
fi

cd "$WORKDIR" || exit 1 # Changing to working directory, if not possible exit


# T3 Validate presence of command line parameters

if [ $# -ne 6 ]; then #Expecting 6 arguments
	echo "${FAIL_PREFIX} Incorrect number of parameters. Usage: $0 -C <URL> -r <REMOTE_HOST> -u <REMOTE_USER>"
	exit 1
fi

while getopts "C:r:u:" opt; do # Accept the flags and require value
	case $opt in
		C) URL="$OPTARG" ;;
		r) REMOTE_HOST="$OPTARG" ;;
		u) REMOTE_USER="$OPTARG" ;;
		*)
			echo "${FAIL_PREFIX} Invalid option -$OPTARG"
			exit 1
			;;
		esac
	done

# Validate presence of required arguments
if [ -z "$URL" ] || [ -z "$REMOTE_HOST" ] || [ -z "$REMOTE_USER" ]; then
	echo "Error: Missing required parameters."
	echo "${FAIL_PREFIX} Usage: $0 -C <URL> -r <REMOTE_HOST> -u <REMOTE_USER>"
	exit 1
fi

echo "Parameters validated:"
echo " URL = $URL"
echo " REMOTE_HOST = $REMOTE_HOST"
echo " REMOTE_USER = $REMOTE_USER"


# HTTPS validation for K2
if [[ "$URL" != https://* ]]; then
	echo "${FAIL_PREFIX} Error: The URL provided with -C must begin with https://"
	echo "Provided: $URL"
	exit 1
fi

echo "HTTPS check passed: $URL"


# T4 Downloading configuration file from $URL command line parameter. If host specific config file is not present use "default.conf"
# All actions logged

CONFIG_URL_BASE="$URL"

HOSTNAME=$(hostname)
HOST_HASH=$(echo -n "$HOSTNAME" | sha256sum | awk '{print $1}')
CONFIG_FILE="${WORKDIR}/${HOST_HASH}.conf"
LOGFILE="/opt/security/logs/socscript.log"

echo "[$(date)] Hostname = $HOSTNAME" >> "$LOGFILE"
echo "[$(date)] Host hash = $HOST_HASH" >> "$LOGFILE"

mkdir -p "$(dirname "$LOGFILE")" # Create directory if it does not exist

echo "[$(date)] Starting config download for $HOSTNAME" >> "$LOGFILE" # Appends to $LOGFILE

if curl -sf "${CONFIG_URL_BASE}/${HOST_HASH}.conf" -o "$CONFIG_FILE"; then
	echo "[$(date)] Downloaded host-specific config: ${HOST_HASH}.conf" >> "$LOGFILE"

else
	echo "[$(date)] Host-specific config not found, using default.conf" >> "$LOGFILE"
	if curl -sf "${CONFIG_URL_BASE}/default.conf" -o "$CONFIG_FILE"; then
		echo "[$(date)] Downloaded default config successfully" >> "$LOGFILE"
	else
		echo "[$(date)] Error: Failed to download any configuration file" >> "$LOGFILE"
		echo "${FAIL_PREFIX} Error: Unable to download configuration file."
		exit 1
	fi
fi

echo "Configuration file ready: $CONFIG_FILE"


# T5 validate integrity of configuration file
echo "[$(date)] Validating configuration file integrity..." >> "$LOGFILE"

CONFIG_SIG="${CONFIG_FILE}.gpg"

# Download matching .gpg signature if not already present
if [ ! -f "$CONFIG_SIG" ]; then
	if ! curl -sf "${CONFIG_URL_BASE}/${HOSTNAME}.conf.gpg" -o "$CONFIG_SIG"; then
		echo "${FAIL_PREFIX} Failed to download signature file for configuration"
		echo "Error: Could not download configuration signature file." >> "$LOGFILE"
		exit 1
	fi
fi

# Confirm the trusted signing key exists on host keyring
if ! gpg --list-keys "soc-sign@dragur.no" >/dev/null 2>&1; then
	echo "[$(date)] ERROR: Required GPG key 'soc-sign@dragur.no' not found." >> "$LOGFILE"
	echo "${FAIL_PREFIX} Error: Missing Dragur SOC signing key."
	exit 1
fi



# Verify signature
if gpg --verify "$CONFIG_SIG" "$CONFIG_FILE" >> "$LOGFILE" 2>&1; then
	echo "[$(date)] Configuration file signature validation passed" >> "$LOGFILE"
else
	echo "[$(date)] Configuration file signature validation failed" >> "$LOGFILE"
	echo "${FAIL_PREFIX} Error: Configuration file integrity validation failed."
	exit 1
fi


# T6 Validate configuration version, and log error if not correct

EXPECTED_VERSION="1.3"
CONFIG_VERSION=$(grep -iE "^version[[:space:]]+[0-9]+\.[0-9]+" "$CONFIG_FILE" | grep -oE "[0-9]+\.[0-9]+")


if [ -z "$CONFIG_VERSION" ]; then
	echo "[$(date)] ERROR: Config version not found in $CONFIG_FILE" >> "$LOGFILE"
	echo "${FAIL_PREFIX} Error: Missing configuration version."
	exit 1
fi

if [[ ! "$CONFIG_VERSION" =~ ^[0-9]+\.[0-9]+$ ]]; then
	echo "${FAIL_PREFIX} Invalid configuration version format ($CONFIG_VERSION). Expected x.x"
	echo "[$(date)] ERROR: version mismatch (found $CONFIG_VERSION, expected $EXPECTED_VERSION)" >> "$LOGFILE"
	exit 1
fi

echo "[$(date)] Configuration version check passed ($CONFIG_VERSION)" >> "$LOGFILE"


# T7 Download the daily threat list and GPG signature

THREATLIST="threatlist-$DATE"
THREAT_URL="${URL}/sigs/${THREATLIST}"
THREAT_FILE="${WORKDIR}/${THREATLIST}"
THREAT_SIG="${THREAT_FILE}.gpg"

echo "[$(date)] Downloading threat list: $THREATLIST" >> "$LOGFILE"


# Download threat list and signature
if ! curl -sf "$THREAT_URL" -o "$THREAT_FILE"; then
	echo "[$(date)] ERROR: Failed to download threat list." >> "$LOGFILE"
	echo "${FAIL_PREFIX} Failed to download threat list."
	exit 1
fi

if ! curl -sf "${THREAT_URL}.gpg" -o "$THREAT_SIG"; then
	echo "[$(date)] ERROR: Failed to download threat list signature." >> "$LOGFILE"
	echo "${FAIL_PREFIX} Missing threat list signature."
	exit 1
fi

if gpg --verify "$THREAT_SIG" "$THREAT_FILE" >> "$LOGFILE" 2>&1; then
	echo "[$(date)] Threat list signature validation passed." >> "$LOGFILE"
else
	echo "[$(date)] ERROR: Threat list signature validation failed." >> "$LOGFILE"
	echo "${FAIL_PREFIX} Threat list integrity validation failed."
	exit 1
fi



# T8 If previous steps are sucessfull write message to STDOUT
echo "[$(date)] All configuration and validation check passed." >> "$LOGFILE"


# T9 Extract logs for upload K8-10
# On mondays, copy the rotated log (access.log.1) to capture the previous days data (sunday)
# All other days copy the current access.log
LOG_SRC="/var/log/apache2/access.log"
UPLOAD_DIR="$WORKDIR/upload"
mkdir -p "$UPLOAD_DIR"

DAY=$(date +%u) # Monday=1, sunday = 7

if [ "$DAY" -eq 1 ]; then
	if [ -f "/var/log/apache2/access.log.1" ]; then
		cp "/var/log/apache2/access.log.1" "$UPLOAD_DIR/access.log"
		echo "[$(date)] Copied rotated log (access.log.1)." >> "$LOGFILE"
	else
		echo "[$(date)] No rotated log found (access.log.1 missing)." >> "$LOGFILE"
	fi
else
	if [ -f "$LOG_SRC" ]; then
		cp "$LOG_SRC" "$UPLOAD_DIR/access.log"
		echo "[$(date)] Copied current access.log." >> "$LOGFILE"
	else
		echo "[$(date)] No access.log found." >> "$LOGFILE"
	fi
fi

echo "[$(date)] Collected apache logs for upload." >> "$LOGFILE"



# T10 Data statisics
# Produce traffic summary. Total access, unique hosts, bytes in 200 responses and count of error codes

REPORT_FILE="$WORKDIR/report.txt"
LOG_FILES="$UPLOAD_DIR/access.log"

echo "[$(date)] Generating traffic report..." >> "$LOGFILE"

echo "==== Daily Web Traffic Report ====" > "$REPORT_FILE"
echo "Generated on: $(date)" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

TOTAL_ACCESS=$(wc -l < "$LOG_FILES")
echo "Total number of accesses: $TOTAL_ACCESS" >> "$REPORT_FILE"

UNIQUE_HOSTS=$(awk '{print $1}' "$LOG_FILES" | sort | uniq | wc -l)
echo "Number of unique clients: $UNIQUE_HOSTS" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Top 20 clients by requests:" >> "$REPORT_FILE"
awk '{print $1}' "$LOG_FILES" | sort | uniq -c | sort -nr | head -20 >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Sum of bytes for successfull responses
BYTES_200=$(awk '$9 == 200 {sum += $10} END {print sum}' "$LOG_FILES")
echo "Total bytes served for HTTPS 200 responses: $BYTES_200" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Count of common 40x codes
for code in 401 402 403 404 405; do
	COUNT=$(awk -v c="$code" '$9 == c {count++} END {print count+0}' "$LOG_FILES")
	echo "Number of HTTPS $code errors: $COUNT" >> "$REPORT_FILE"
done
echo >> "$REPORT_FILE"

ERR_50X=$(awk '$9 ~ /^5[0-9][0-9]$/ {count++} END {print count +0}' "$LOG_FILES")
echo "Number of 50x series errors combined: $ERR_50X" >> "$REPORT_FILE"

echo "[$(date)] Report generation complete: $REPORT_FILE" >> "$LOGFILE"
echo "STAGE10=GOOD"


# T11 404 URL statistics

OUTPUT_404="$WORKDIR/404url"

echo "[$(date)] Generating 404 URL statistics..." >> "$LOGFILE"

awk '$9 == 404 {print $1, $7}' "$LOG_FILES" | sort > "$WORKDIR/404_raw.tmp"

awk '
{
	url = $2
	host = $1
	count[url]++
	hosts[url][host] = 1
}
END {
	for (u in count) {
		uh = 0
		for (h in hosts[u]) uh++
		printf "%s, %d, %d\n", u, count[u], uh
	}
}' "$WORKDIR/404_raw.tmp" | sort -t, -k3,3nr > "$OUTPUT_404"

echo
echo "Top 10 URLs by unique hosts (404 errors):"
head -10 "$OUTPUT_404"
echo

echo "[$(date)] 404 URL statistics written to: $OUTPUT_404" >> "$LOGFILE"
echo "STAGE11=GOOD"


# T12 List requisite files and audit (NOT WORKING AS INTENDED)
# From config, find webroot
# Change activity, not used files and executables
echo "[$(date)] Starting file checks..." >> "$LOGFILE"

WEBROOT=$(grep -i '^webroot=' "$CONFIG_FILE" | cut -d"=" -f2 | tr -d '"')

if [ -z "$WEBROOT" ]; then
	echo "[$(date)] WARNING: 'webroot' not defined in config. skipping file checks." >> "$LOGFILE"
	echo "STAGE12=WARNING"
	echo "${FAIL_PREFIX} 'webroot' not defined in config. skipping file checks"
else
	RECENT_MODIFIED="$WORKDIR/recent_modified.txt"
	OLD_UNACCESSED="$WORKDIR/old_unaccessed.txt"
	TMP_EXECUTABLES="$WORKDIR/tmp_executables.txt"

	echo "Files in $WEBROOT modified in the last 48 hours:" > "$RECENT_MODIFIED"
	find "$WEBROOT" -type f -mtime -2 -print >> "$RECENT_MODIFIED" 2>>"$LOGFILE"
	echo "[$(date)] Created $RECENT_MODIFIED" >> "$LOGFILE"

	echo "Files in $WEBROOT not accessed in 60 days or more:" > "$OLD_UNACCESSED"
	find "$WEBROOT" -type f -mtime +60 -print >> "$OLD_UNACCESSED" 2>>"$LOGFILE"
	echo "[$(date)] Created $OLD_UNACCESSED" >> "$LOGFILE"

	echo "Executable files in /tmp /var/tmp:" > "$TMP_EXECUTABLES"
	find /tmp /var/tmp -type f -perm /111 -print >> "$TMP_EXECUTABLES" 2>>"$LOGFILE"
	echo "[$(date)] Created $TMP_EXECUTABLES" >> "$LOGFILE"

	echo
	echo "Audit summary:"
	echo " - Modified last 48h: $(wc -l < "$RECENT_MODIFIED") files"
	echo " - Not accessed 60d+: $(wc -l < "$OLD_UNACCESSED") files"
	echo " - Executables in /tmp or /var/tmp: $(wc -l < "$TMP_EXECUTABLES") files"
	echo

	echo "[$(date)] Filecheck and audit completed sucessfully." >> "$LOGFILE"
	echo "STAGE12=GOOD"
fi


# T13 Ensure filesystem mounted at /data/webstatic is mounted as READ ONLY & NON EXECUTABLE
MOUNT_POINT="/data/webstatic"
STAGE13_STATUS="GOOD"

if ! grep -q " ${MOUNT_POINT} " /proc/mounts 2>/dev/null; then
	echo "[$(date)] WARNING: ${MOUNT_POINT} not mounted." >> "$LOGFILE"
	echo "STAGE13=WARNING"
	STAGE13_STATUS="WARNING"
else
	if command -v findmnt >/dev/null 2>&1; then
		MOPTS=$(findmnt -n -o OPTIONS --target "$MOUNT_POINT" 2>>"$LOGFILE" || true)
	else
		MOPTS=$(awk -v mp="$MOUNT_POINT" '$2==mp {print $4; exit}' /proc/mounts 2>>"$LOGFILE" || true)
	fi

	if echo "$MOPTS" | tr ',' '\n' | grep -q '^ro$' && echo "$MOPTS" | tr ',' '\n' | grep -q '^noexec$'; then
		echo "[$(date)] Mount $MOUNT_POINT options contain 'ro' and 'noexec' $MOPTS" >> "$LOGFILE"
		echo "STAGE13=GOOD"
	else
		echo "[$(date)] WARNING: Mount $MOUNT_POINT does not have required options. Actual $MOPTS" >> "$LOGFILE"
		echo "STAGE13=WARNING"
		STAGE13_STATUS="WARNING"
	fi
fi


# T14 Webserver configuration integrity check

WEBCONFIG_REF=$(grep -i '^webconfigref=' "$CONFIG_FILE" | cut -d'=' -f2- | tr -d '"' | tr -d "'" || true)

LIVE_CONF="/etc/apache2/apache2.conf"

DIFF_FILE="$WORKDIR/webconfig.diff"
STAGE14_STATUS="GOOD"

echo "[$(date)] Starting T14: Comparing live config $LIVE_CONF to reference $WEBCONFIG_REF" >> "$LOGFILE"

if [ ! -f "$WEBCONFIG_REF" ]; then
	echo "[$(date)] ERROR: Reference config $WEBCONFIG_REF not found." >> "$LOGFILE"
	echo "STAGE14=WARNING"
	STAGE14_STATUS="WARNING"
elif [ ! -f "$LIVE_CONF" ]; then
	echo "[$(date)] ERROR: Live webserver config $LIVE_CONF not found." >> "$LOGFILE"
	echo "STAGE14=WARNING"
	STAGE14_STATUS="WARNING"
else
	diff -u "$WEBCONFIG_REF" "$LIVE_CONF" > "$DIFF_FILE" 2>>"$LOGFILE" || true

	if [ -s "$DIFF_FILE" ]; then
		echo "[$(date)] Webserver config changed. Diff saved to $DIFF_FILE" >> "$LOGFILE"
		echo "STAGE14=WARNING"
		STAGE14_STATUS="WARNING"
	else
		echo "[$(date)] Webserver config unchanged" >> "$LOGFILE"
		rm -f "$DIFF_FILE" 2>/dev/null || true
		echo "STAGE14=GOOD"
		STAGE14_STATUS="GOOD"
	fi
fi

echo "[$(date)] T14 Status: $STAGE14_STATUS" >> "$LOGFILE"



# T15 Firewall and listening ports integrity check

STAGE15_STATUS="GOOD"
FIREWALL_YESTERDAY="/opt/security/firewall.yesterday"
PORTS_YESTERDAY="/opt/security/ports.yesterday"
FIREWALL_NOW="$WORKDIR/firewall.now"
PORTS_NOW="$WORKDIR/ports.now"
FIREWALL_DIFF="$WORKDIR/firewall.diff"
PORTS_DIFF="$WORKDIR/port.diff"

echo "[$(date)] Starting T15: Checking firewall and listening ports integrity..." >> "$LOGFILE"

# Capture current firewall rules
if command -v iptables >/dev/null 2>&1; then
	iptables -L -v -n --line-numbers > "$FIREWALL_NOW" 2>>"$LOGFILE"
elif command -v iptables-save >/dev/null 2>&1; then
	sudo iptables-save > "$FIREWALL_NOW" 2>>"$LOGFILE"
else
	echo "[$(date)] WARNING: No iptables tool found on system." >> "$LOGFILE"
	echo "STAGE15=WARNING"
	STAGE15_STATUS="WARNING"
	echo "${FAIL_PREFIX} No iptables tool found on system"
fi

# Captire current listening ports
if command -v ss >/dev/null 2>&1; then
	ss -tuln | sort > "$PORTS_NOW" 2>>"$LOGFILE"
elif command -v netstat >/dev/null 2>&1; then
	netstat -tuln | sort > "$PORTS_NOW" 2>>"$LOGFILE"
else
	echo "[$(date)] WARNING: No tool available to list listening ports (ss/netstat)." >> "$LOGFILE"
	echo "STAGE15=WARNING"
	STAGE15_STATUS="WARNING"
	echo "${FAIL_PREFIX} No tool available to list listening ports"
fi

# Compare current firewall to yesterdays
if [ -f "$FIREWALL_YESTERDAY" ]; then
	diff -u "$FIREWALL_YESTERDAY" "$FIREWALL_NOW" > "$FIREWALL_DIFF" 2>>"$LOGFILE" || true
	if [ -s "$FIREWALL_DIFF" ]; then
		echo "[$(date)] Firewall rules have changed. Diff saved to $FIREWALL_DIFF" >> "$LOGFILE"
		STAGE15_STATUS="WARNING"
	else
		echo "[$(date)] Firewall rules unchanged." >> "$LOGFILE"
		rm -f "$FIREWALL_DIFF" 2>/dev/null || true
	fi
else
	echo "[$(date)] No previous firewall snapshot found. Creating baseline at $FIREWALL_YESTERDAY" >> "$LOGFILE"
	cp "$FIREWALL_NOW" "$FIREWALL_YESTERDAY"
fi

# Compare current listening ports to yesterdays
if [ -f "$PORTS_YESTERDAY" ]; then
	diff -u "$PORTS_YESTERDAY" "$PORTS_NOW" > "$PORTS_DIFF" 2>>"$LOGFILE" || true
	if [ -s "$PORTS_DIFF" ]; then
		echo "[$(date)] Listening ports have changed. Diff saved to $PORTS_DIFF" >> "$LOGFILE"
		STAGE15_STATUS="WARNING"
	else
		echo "[$(date)] Listening ports unchanged." >> "$LOGFILE"
		rm -f "$PORTS_DIFF" 2>/dev/null || true
	fi
else
	echo "[$(date)] No previous port snapshot found. Creating baseline at $PORTS_YESTERDAY" >> "$LOGFILE"
	cp "$PORTS_NOW" "$PORTS_YESTERDAY"
fi

cp "$FIREWALL_NOW" "$FIREWALL_YESTERDAY" 2>>"$LOGFILE" || true
cp "$PORTS_NOW" "$PORTS_YESTERDAY" 2>>"$LOGFILE" || true

echo "[$(date)] T15 status: $STAGE15_STATUS" >> "$LOGFILE"
echo "STAGE15=$STAGE15_STATUS"


# T16 Validation archive

VALIDATION_DIR="/opt/security/validation"
VALIDATION_FILE="$VALIDATION_DIR/validation.txt"
WEBCONFIG_COPY="$VALIDATION_DIR/webconfig-$DATE"
FIREWALL_COPY="$VALIDATION_DIR/firewall-$DATE"

echo "[$(date)] Starting T16. Saving validation outputs..." >> "$LOGFILE"

mkdir -p "$VALIDATION_DIR"

{
	echo "==== Validation Report===="
	echo "Generated: $(date)"
	echo
	echo "---- T12 File Audit Summary ----"
	echo "Recent modified files (last 48h):"
	cat "$WORKDIR/recent_modified.txt" 2>/dev/null || echo "N/A"
	echo
	echo "Old unaccessed files (60+ days):"
	cat "$WORKDIR/old_unaccessed.txt" 2>/dev/null || echo "N/A"
	echo
	echo "Executables in /tmp or /var/tmp:"
	cat "$WORKDIR/tmp_executables.txt" 2>/dev/null || echo "N/A"
	echo
	echo "---- T13 Filesystem Mount Check ----"
	grep "STAGE13" "$LOGFILE" | tail -1 || echo "No mount data found."
	echo
	echo "---- T14 Web Config Diff ----"
	if [ -f "$WORKDIR/webconfig.diff" ]; then
		cat "$WORKDIR/webconfig.diff"
	else
		echo "No configuration changes detected."
	fi
	echo
	echo "---- T15 Firewall & Ports Diff ----"
	if [ -f "$WORKDIR/firewall.diff" ]; then
		cat "$WORKDIR/firewall.diff"
	else
		echo "No firewall changes detected."
	fi
	echo
	if [ -f "$WORKDIR/port.diff" ]; then
		cat "$WORKDIR/port.diff"
	else
		echo "No port changes detected."
	fi
} > "$VALIDATION_FILE"

echo "[$(date)] Validation summary written to $VALIDATION_FILE" >> "$LOGFILE"


if [ -f "$LIVE_CONF" ]; then
	cp "$LIVE_CONF" "$WEBCONFIG_COPY"
	echo "[$(date)] Copied current webserver config to $WEBCONFIG_COPY" >> "$LOGFILE"
else
	echo "[$(date)] WARNING: Webserver config not found at $LIVE_CONF" >> "$LOGFILE"
	echo "${FAIL_PREFIX} Webserver config not found at $LIVE_CONF"
fi

if [ -f "$WORKDIR/firewall.now" ]; then
	cp "$WORKDIR/firewall.now" "$FIREWALL_COPY"
	echo "[$(date)] Copied current firewall rules to $FIREWALL_COPY" >> "$LOGFILE"
else
	echo "[$(date)] WARNING: Firewall rules not found in $WORKDIR/firewall.now" >> "$LOGFILE"
	echo "${FAIL_PREFIX} Firewall rules not found in $WORKKDIR/firewall.now"
fi

echo "[$(date)] T16 completed successfully" >> "$LOGFILE"
echo "STAGE16=GOOD"



# T17 Check disk space utilisation

echo "[$(date)] Starting T17. Checking disk space utilisation..." >> "$LOGFILE"

DISK_REPORT="$WORKDIR/diskspace.txt"
STAGE17_STATUS="GOOD"

echo "==== Disk Space Report ====" > "$DISK_REPORT"
echo "Generated: $(date)" >> "$DISK_REPORT"
echo >> "$DISK_REPORT"
printf "%-25s %-10s %-10s %-10s %-10s\n" "Filesystem" "Size(MB)" "Used(MB)" "Available(MB)" "Use%" >> "$DISK_REPORT"
echo "---------------------------------------------------------------------------------------------" >> "$DISK_REPORT"

df -Pm | awk 'NR>1 {print $1, $2, $3, $4, $5, $6}' | while read -r fs size used avail use mount; do
	USEPCT=$(echo "$use" | tr -d "%")

	printf "%-25s %-10s %-10s %-10s %-10s\n" "$mount" "$size" "$used" "$avail" "$use" >> "$DISK_REPORT"

	if [[ "$USEPCT" =~ ^[0-9]+$ ]] && [[ "$avail" =~ ^[0-9]+$ ]]; then
		if [ "$USEPCT" -ge 90 ] || [ "$avail" -lt 3128  ]; then
			echo "[$(date)] WARNING: $mount is low on space: ${use} used, ${avail}MB free." >> "$LOGFILE"
			echo "WARNING: $mount is low on space: ${use} used, ${avail}MB free." >> "$DISK_REPORT"
			STAGE17_STATUS="WARNING"
		fi
	else
		echo "[$(date)] Skipping invalid line. Used=$use avail=$avail mount=$mount" >> "$LOGFILE"
	fi
done


echo >> "$DISK_REPORT"
echo "[$(date)] Disk space check complete. Status: $STAGE17_STATUS" >> "$LOGFILE"
echo "STAGE17=$STAGE17_STATUS"


# T18 Detect IPs causing >= N errors from previous days logs

echo "[$(date)] Starting T18: Detecting error IPs..." >> "$LOGFILE"

STAGE18_STATUS="GOOD"
ERROR_THRESHOLD=$(grep -i '^hostthreshold=' "$CONFIG_FILE" | cut -d'=' -f2 | tr -d '"[:space:]"')

if ! [[ "$ERROR_THRESHOLD" =~ ^[0-9]+$ ]]; then
	ERROR_THRESHOLD=10
	echo "[$(date)] WARNING: Invalid or missing error treshold in config. Using default value of $ERROR_THRESHOLD." >> "$LOGFILE"
fi

if [ ! -f "$UPLOAD_DIR/access.log" ]; then
	echo "[$(date)] ERROR: No access log found in $UPLOAD_DIR for T18." >> "$LOGFILE"
	STAGE18_STATUS="WARNING"
	echo "${FAIL_PREFIX} No access log found in $UPLOAD_DIR for T18"
else
	cd "$WORKDIR" || exit 1

	declare -A ERROR_CODES=(
		["401"]="401"
		["403"]="403"
		["404"]="404"
		["50x"]="5[0-9][0-9]"
)

	for code in "${!ERROR_CODES[@]}"; do
		pattern="${ERROR_CODES[$code]}"
		outfile="${WORKDIR}/${code}errors.txt"

		awk -v pat="$pattern" -v N="$ERROR_THRESHOLD" '$9 ~ pat {count[$1]++}
			END {
				for (ip in count)
					if (count[ip] >= N)
						printf "%-20s %d\n", ip, count[ip];
			}' "$UPLOAD_DIR/access.log" > "$outfile.tmp"

		if [ -s "$outfile.tmp" ]; then
			mv "$outfile.tmp" "$outfile"
			echo "[$(date)] Created $outfile (threshold $ERROR_THRESHOLD)." >> "$LOGFILE"
		else
			rm -f "$outfile.tmp"
		fi
	done
fi

echo "[$(date)] T18 complete. Status: $STAGE18_STATUS" >> "$LOGFILE"
echo "STAGE18=$STAGE18_STATUS"



# T19 Check logs for high risk paths

echo "[$(date)] Starting T19. Checking for high risk path accesses..." >> "$LOGFILE"

STAGE19_STATUS="GOOD"
RISKPATHS=$(grep -i '^RISKPATHS=' "$CONFIG_FILE" | cut -d'=' -f2 | tr -d '"[:space:]')

if [ -z "$RISKPATHS" ]; then
	echo "[$(date)] WARNING: No riskpaths defined in configuration file." >> "$LOGFILE"
	STAGE19_STATUS="WARNING"
else

	if [ ! -f "$UPLOAD_DIR/access.log" ]; then
		echo "[$(date)] ERROR: Access log missing for T19." >> "$LOGFILE"
		STAGE19_STATUS="WARNING"
		echo "${FAIL_PREFIX} Access log missing for T19"
	else
		RISK_FILE="${WORKDIR}/riskaccess.txt"
		TMP_FILE="${RISK_FILE}.tmp"
		rm -f "$TMP_FILE"

		echo "[$(date)] Checking for paths: $RISKPATHS" >> "$LOGFILE"

		IFS=',' read -ra PATHS <<< "$RISKPATHS"
		for path in "${PATHS[@]}"; do
			grep -E "$path" "$UPLOAD_DIR/access.log" >> "$TMP_FILE"
		done

		if [ -s "$TMP_FILE" ]; then
			mv "$TMP_FILE" "$RISK_FILE"
			COUNT=$(wc -l < "$RISK_FILE")
			echo "[$(date)] Found $COUNT access attempts to high risk paths." >> "$LOGFILE"
			STAGE19_STATUS="WARNING"
		else
			echo "[$(date)] No high risk path accesses detected." >> "$LOGFILE"
			rm -f "$TMP_FILE"
		fi
	fi
fi

echo "[$(date)] T19 complete. Status: $STAGE19_STATUS" >> "$LOGFILE"
echo "STAGE19=$STAGE19_STATUS"



# T20 Check IP addresses against threat intelligence list

echo "[$(date)] Starting T20. Checking IPs against threat intelligence list..." >> "$LOGFILE"

STAGE20_STATUS="GOOD"
THREAT_FILE="${WORKDIR}/threats.tsv"
TMP_FILE="${WORKDIR}/threats.tmp"
CTI_URL=$(grep -i '^CTIurl=' "$CONFIG_FILE" | cut -d'=' -f2 | tr -d '"[:space:]')

if [ -z "$CTI_URL" ]; then
	echo "[$(date)] ERROR: No CTIurl found in configuration file." >> "$LOGFILE"
	STAGE20_STATUS="WARNING"
	echo "${FAIL_PREFIX} No CTIurl found in configuration file."
else
	if [[ "$CTI_URL" =~ ^https:// ]]; then
		THREATLIST="${WORKDIR}/threatlist.txt"
		curl -fsSL "$CTI_URL" -o "$THREATLIST"
		if [ $? -ne 0 ] || [ ! -s "$THREATLIST" ]; then
			echo "[$(date)] ERROR: Failed to download threat list from $CTI_URL" >> "$LOGFILE"
			STAGE20_STATUS="WARNING"
			echo "${FAIL_PREFIX} Failed to download threat list from $CTI_URL"
		else
			echo "[$(date)] Threat list downloaded successfully." >> "$LOGFILE"

			if [ ! -f "$UPLOAD_DIR/access.log" ]; then
				echo "[$(date)] ERROR: Access log missing for T20." >> "$LOGFILE"
				STAGE20_STATUS="WARNING"
				echo "${FAIL_PREFIX} Access log missing for T20"
			else
				rm -f "$TMP_FILE"
				touch "$TMP_FILE"

				while read -r badip; do
					[[ "$badip" =~ ^#.*$ || -z "$badip" ]] && continue
					grep -E "^$badip " "$UPLOAD_DIR/access.log" | awk '{ printf "%s\t%s\t%s\n", $4, $1, $7 }' >> "$TMP_FILE"
				done < "$THREATLIST"

				if [ -s "$TMP_FILE" ]; then
					mv "$TMP_FILE" "$THREAT_FILE"
					COUNT=$(wc -l < "$THREAT_FILE")
					echo "[$(date)] Found $COUNT matches with known threat IPs." >> "$LOGFILE"
					STAGE20_STATUS="WARNING"
				else
					echo "[$(date)] No threat IP matches found." >> "$LOGFILE"
					rm -f "$TMP_FILE"
				fi
			fi
		fi
	else
		echo "[$(date)] ERROR: CTI URL is not HTTPS. Must start with 'https://'" >> "$LOGFILE"
		STAGE20_STATUS="WARNING"
		echo "${FAIL_PREFIX} CTI URL is not HTTPS."
	fi
fi

echo "[$(date)] T20 Complete. Status: $STAGE20_STATUS" >> "$LOGFILE"
echo "STAGE20=$STAGE20_STATUS"



# T21 Packaging, signing and checksumming

echo "[$(date)] Starting T21. Packaging and signing report..." >> "$LOGFILE"

STAGE21_STATUS="GOOD"


TIMESTAMP=$(date +%Y%m%d-%H)
REPORT_BASE="socscript-${HOSTNAME}-${TIMESTAMP}"
OUTPUT_DIR="/opt/security"
TAR_FILE="${OUTPUT_DIR}/${REPORT_BASE}.tar.gz"
SIG_FILE="${TAR_FILE}.gpg"
SHA_FILE="${TAR_FILE}.sha256"

echo "[$(date)] Creating archive: ${TAR_FILE}" >> "$LOGFILE"

tar -czf "$TAR_FILE" -C "$WORKDIR" . 2>>"$LOGFILE"
if [ $? -ne 0 ] || [ ! -s "$TAR_FILE" ]; then
	echo "[$(date)] ERROR: Failed to create tar archive." >> "$LOGFILE"
	STAGE21_STATUS="WARNING"
	echo "${FAIL_PREFIX} Failed to create tar archive."
else
	echo "[$(date)] Archive created successfully." >> "$LOGFILE"
fi

if gpg --list-keys "soc-ingest@dragur.no" >/dev/null 2>&1; then
	echo "[$(date)] Signing tar.gz with soc-ingest@dragur.no..." >> "$LOGFILE"
	if gpg --yes --output "$SIG_FILE" --local-user "soc-ingest@dragur.no" --detach-sign "$TAR_FILE" 2>>"$LOGFILE"; then
		echo "[$(date)] GPG signature created: $SIG_FILE" >> "$LOGFILE"
	else
		echo "[$(date)] ERROR: GPG signing failed." >> "$LOGFILE"
		STAGE21_STATUS="WARNING"
		echo "${FAIL_PREFIX} GPG signing failed"
	fi
else
	echo "[$(date)] WARNING: GPG key 'soc-ingest@dragur.no' not found. Skipping signing step." >> "$LOGFILE"
	STAGE21_STATUS="WARNING"
	echo "${FAIL_PREFIX} GPG key 'soc-ingest@dragur.no' not found. Skipping signing step."
fi

echo "[$(date)] Generating SHA256 checksum..." >> "$LOGFILE"

(cd "$(dirname "$TAR_FILE")" && sha256sum "$(basename "$TAR_FILE")" > "$(basename "$SHA_FILE")")


if [ -s "$SHA_FILE" ]; then
	echo "[$(date)] SHA256 checksum saved to $SHA_FILE" >> "$LOGFILE"

else
	echo "[$(date)] ERROR: Failed to create checksum file." >> "$LOGFILE"
	STAGE21_STATUS="WARNING"
	echo "${FAIL_PREFIX} Failed to create checksum file."
fi

if [ "$STAGE21_STATUS" = "GOOD" ]; then
	echo "[$(date)] T21 completed successfully. Archive ready for upload." >> "$LOGFILE"
else
	echo "[$(date)] T21 completed with warnings. Check log for details." >> "$LOGFILE"
	echo "${FAIL_PREFIX} T21 completed with warnings. Check log for details."
fi

echo "STAGE21=$STAGE21_STATUS"



# T22 Upload package to server

echo "[$(date)] Starting T22. Uploading to server..." >> "$LOGFILE"
STAGE22_STATUS="GOOD"

YEAR=$(date +%Y)
MONTH=$(date +%m)

SSH_IDENTITY="/opt/security/useridentity.id.${REMOTE_USER}"

if [ ! -f "$SSH_IDENTITY" ]; then
	echo "[$(date)] ERROR: SSH identity file $SSH_IDENTITY not found." >> "$LOGFILE"
	echo "${FAIL_PREFIX} Missing SSH identity file for user $REMOTE_USER."
	STAGE22_STATUS="WARNING"
else
	chmod 600 "$SSH_IDENTITY"
fi

REMOTE_DIR="/submission/${HOSTNAME}/${YEAR}/${MONTH}/"

for f in "$TAR_FILE" "$SIG_FILE" "$SHA_FILE"; do
	if [ ! -f "$f" ]; then
		echo "[$(date)] ERROR: Missing expected file for upload: $f" >> "$LOGFILE"
		STAGE22_STATUS="WARNING"
		echo "${FAIL_PREFIX} Missing expected file for upload: $f"
	fi
done

if [ "$STAGE22_STATUS" = "GOOD" ]; then
	echo "[$(date)] Connecting to $REMOTE_HOST on port 31337..." >> "$LOGFILE"

	ssh -i "$SSH_IDENTITY" -p 31337 "${REMOTE_USER}@${REMOTE_HOST}" "mkdir -p '$REMOTE_DIR'" 2>>"$LOGFILE"
	if [ $? -ne 0 ]; then
		echo "[$(date)] ERROR: Failed to create remote directory $REMOTE_DIR" >> "$LOGFILE"
		STAGE22_STATUS="WARNING"
		echo "${FAIL_PREFIX} Failed to create remote directory $REMOTE_DIR"

	else
		rsync -avz -e "ssh -i $SSH_IDENTITY -p 31337" "$TAR_FILE" "$SIG_FILE" "$SHA_FILE" "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}" >> "$LOGFILE" 2>&1

		if [ $? -eq 0 ]; then
			echo "[$(date)] Upload completed successfully to ${REMOTE_HOST}:${REMOTE_DIR}" >> "$LOGFILE"
		else
			echo "[$(date)] ERROR: rsync upload failed to ${REMOTE_HOST}:${REMOTE_DIR}" >> "$LOGFILE"
			STAGE22_STATUS="WARNING"
			echo "${FAIL_PREFIX} rsync upload failed to ${REMOTE_HOST}:${REMOTE_DIR}"
		fi
	fi
fi

echo "[$(date)] T22 completed with status: $STAGE22_STATUS" >> "$LOGFILE"
echo "STAGE22=$STAGE22_STATUS"



# T23 Validate upload integrity on remote server

echo "[$(date)] Starting T23. Validating uploaded archive integrity..." >> "$LOGFILE"
STAGE23_STATUS="GOOD"

REMOTE_SHA_FILE=$(basename "$SHA_FILE")
REMOTE_CHECK_CMD="
if [ -f '${REMOTE_DIR}/${REMOTE_SHA_FILE}' ]; then
	echo '[INFO] Found remote SHA file: ${REMOTE_DIR}/${REMOTE_SHA_FILE}'
	cd '${REMOTE_DIR}' && sha256sum -c '${REMOTE_SHA_FILE}'
else
	echo '${FAIL_PREFIX} Remote SHA file not found: ${REMOTE_DIR}/${REMOTE_SHA_FILE}'
	exit 1
fi
"

sleep 2

ssh -i "$SSH_IDENTITY" -p 31337 "${REMOTE_USER}@${REMOTE_HOST}" "$REMOTE_CHECK_CMD" >> "$LOGFILE" 2>&1

if [ $? -eq 0 ]; then
	echo "[$(date)] SHA256 validation successful on remote host ${REMOTE_HOST}" >> "$LOGFILE"
	echo "STAGE23=$STAGE23_STATUS"
else
	echo "[$(date)] ERROR: SHA256 validation failed on ${REMOTE_HOST}" >> "$LOGFILE"
	echo "[$(date)] Remote validation command: $REMOTE_CHECK_CMD" >> "$LOGFILE"
	echo '${FAIL_PREFIX} SHA256 validation failed on ${REMOTE_HOST}'

	ssh -i "$SSH_IDENTITY" -p 31337 "${REMOTE_USER}@${REMOTE_HOST}" "ls -l '${REMOTE_DIR}'" >> "$LOGFILE" 2>&1

	STAGE23_STATUS="WARNING"
	echo "STAGE23=$STAGE23_STATUS"
fi

echo "[$(date)] T23 completed with status: $STAGE23_STATUS" >> "$LOGFILE"



# T24 Final report of upload status and verification

echo "[$(date)] Starting T24. Generating final upload summary..." >> "$LOGFILE"

STAGE24_STATUS="GOOD"

UPLOAD_NAME=$(basename "$TAR_FILE")
UPLOAD_SIZE_MB=$(du -m "$TAR_FILE" | cut -f1)
TIMESTAMP_FULL=$(date +%Y%m%d-%H:%M)

if [ -f "$TAR_FILE" ]; then
	echo "[$(date)] Upload summary: File '$UPLOAD_NAME' size ${UPLOAD_SIZE_MB}MB" >> "$LOGFILE"
	echo "Upload file: $UPLOAD_NAME (${UPLOAD_SIZE_MB}MB)"
	echo "socscript Check ${HOSTNAME} ${TIMESTAMP_FULL} OK"
else
	echo "[$(date)] ERROR: Upload file '$TAR_FILE' not found for reporting." >> "$LOGFILE"
	echo "socscript Check ${HOSTNAME} ${TIMESTAMP_FULL} FAILED"
	STAGE24_STATUS="WARNING"
fi

echo "[$(date)] T24 completed with status: $STAGE24_STATUS" >> "$LOGFILE"
echo "STAGE24=$STAGE24_STATUS"
