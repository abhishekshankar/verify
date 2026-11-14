#!/usr/bin/env bash
# NEW PRIVATE EC2 TARGET ONLY. Does not read source secrets, restore data, enable
# an application writer, start the bridge/Caddy, change DNS or modify source AWS.
set -euo pipefail
umask 077

if [[ $# -ne 7 ]]; then
  echo 'usage: install_ec2_target.sh EXPECTED_INSTANCE_ID EXPECTED_ACCOUNT APP_TAR APP_SHA256 RELEASE_ID SOURCE_PRIVATE_IP HOSTNAME' >&2
  exit 2
fi
expected_instance=$1
expected_account=$2
app_tar=$3
app_sha256=$4
release_id=$5
source_ip=$6
public_hostname=$7
[[ $(id -u) == 0 ]] || { echo 'Run through SSM as root on the new target.' >&2; exit 2; }
[[ $expected_instance =~ ^i-[0-9a-f]{17}$ && $expected_account =~ ^[0-9]{12}$ && $app_sha256 =~ ^[0-9a-f]{64}$ && $release_id =~ ^[0-9a-f]{12,64}$ ]] || exit 2
[[ $public_hostname == ledger.optimise.work ]] || { echo 'Unexpected hostname.' >&2; exit 2; }
[[ ! -e /etc/verify/target-install.json && ! -e /opt/verify/current ]] || { echo 'Target already initialized; inspect state instead of overwriting.' >&2; exit 2; }
source /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 && $(uname -m) == aarch64 ]] || { echo 'Expected Ubuntu24.04 ARM64.' >&2; exit 2; }
python3 - "$source_ip" <<'PY'
import ipaddress,sys
address=ipaddress.ip_address(sys.argv[1])
assert address.version==4 and address.is_private and not address.is_loopback
PY
metadata_token=$(curl --noproxy '*' --silent --show-error --fail --connect-timeout 2 --max-time 5 -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' http://169.254.169.254/latest/api/token)
identity=$(curl --noproxy '*' --silent --show-error --fail --connect-timeout 2 --max-time 5 -H "X-aws-ec2-metadata-token: $metadata_token" http://169.254.169.254/latest/dynamic/instance-identity/document)
unset metadata_token
python3 -c 'import json,sys; i=json.loads(sys.argv[1]); assert i["instanceId"]==sys.argv[2] and i["accountId"]==sys.argv[3] and i["region"]=="us-west-2"' "$identity" "$expected_instance" "$expected_account"
unset identity
printf '%s  %s\n' "$app_sha256" "$app_tar" | sha256sum --check --status

# Package installation is limited to this fresh host. Block package auto-starts
# for public-facing services until configuration, permissions and data are ready.
systemctl mask verify.service verify-migration.service caddy.service
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends postgresql-16 postgresql-client-16 pgbackrest caddy python3-venv python3-pip python3-boto3 ca-certificates curl openssl unattended-upgrades

for account in verify verify-migration; do
  if ! id "$account" >/dev/null 2>&1; then
    useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin "$account"
  fi
done
install -d -m 0755 /opt/verify/releases /etc/verify /etc/verify/tls
install -d -m 0700 /etc/verify/secrets
release_dir=/opt/verify/releases/$release_id
install -d -m 0755 "$release_dir"
python3 - "$app_tar" "$release_dir" <<'PY'
import pathlib,sys,tarfile
root=pathlib.Path(sys.argv[2])
with tarfile.open(sys.argv[1],"r:gz") as source:
    total=0
    for item in source.getmembers():
        path=pathlib.PurePosixPath(item.name)
        if path.is_absolute() or ".." in path.parts or not (item.isfile() or item.isdir()):
            raise SystemExit("Unsafe app archive member")
        total+=item.size
        if item.size>8*1024*1024 or total>32*1024*1024:
            raise SystemExit("App archive exceeds reviewed bounds")
    source.extractall(root,filter="data")
PY
chown -R root:root "$release_dir"
find "$release_dir" -type d -exec chmod 0755 '{}' +
find "$release_dir" -type f -exec chmod 0644 '{}' +
python3 -m venv "$release_dir/.venv"
"$release_dir/.venv/bin/python" -m pip install --disable-pip-version-check 'psycopg[binary]==3.2.3' 'psycopg_pool==3.3.3'
chmod -R a+rX "$release_dir/.venv"
ln -s "$release_dir" /opt/verify/current

install -d -m 0700 -o postgres -g postgres /etc/postgresql/16/main/tls
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj '/CN=Verify local PostgreSQL' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1' \
  -keyout /etc/postgresql/16/main/tls/server-key.pem -out /etc/postgresql/16/main/tls/server.pem 2>/dev/null
chown postgres:postgres /etc/postgresql/16/main/tls/server-key.pem /etc/postgresql/16/main/tls/server.pem
chmod 0600 /etc/postgresql/16/main/tls/server-key.pem
chmod 0644 /etc/postgresql/16/main/tls/server.pem
install -m 0644 /etc/postgresql/16/main/tls/server.pem /etc/verify/tls/postgres-ca.pem
install -m 0644 "$release_dir/hosted/lightsail/host/postgresql.conf" /etc/postgresql/16/main/conf.d/verify.conf
install -m 0640 -o root -g postgres "$release_dir/hosted/lightsail/host/pg_hba.conf" /etc/postgresql/16/main/pg_hba.conf
systemctl restart postgresql@16-main.service
install -m 0644 "$release_dir/hosted/lightsail/host/app.env.example" /etc/verify/app.env
printf 'VERIFY_MIGRATION_SOURCE=http://%s:8080\n' "$source_ip" > /etc/verify/migration.env
chmod 0644 /etc/verify/migration.env
install -d -m 0700 -o verify-migration -g verify-migration /var/lib/verify-migration
printf '{"version":1,"mode":"source","targetActivated":false}\n' > /var/lib/verify-migration/state.json
chown verify-migration:verify-migration /var/lib/verify-migration/state.json
chmod 0600 /var/lib/verify-migration/state.json

cat > /etc/caddy/Caddyfile <<'CADDY'
ledger.optimise.work {
    tls {
        issuer acme {
            disable_tlsalpn_challenge
        }
    }
    reverse_proxy 127.0.0.1:8082
    header Strict-Transport-Security "max-age=31536000"
}
CADDY
chmod 0644 /etc/caddy/Caddyfile
caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
systemctl unmask verify.service verify-migration.service caddy.service
for unit in verify.service verify-migration.service verify-backup.service verify-backup.timer; do
  install -m 0644 "$release_dir/hosted/lightsail/host/$unit" "/etc/systemd/system/$unit"
done
systemctl daemon-reload
systemctl disable caddy.service verify.service verify-migration.service verify-backup.timer
python3 - "$expected_instance" "$expected_account" "$app_sha256" "$release_id" <<'PY'
from datetime import datetime,timezone
import json,sys
record=dict(instanceId=sys.argv[1],accountId=sys.argv[2],appArchiveSha256=sys.argv[3],releaseId=sys.argv[4],
    installedAtUtc=datetime.now(timezone.utc).isoformat(),status="PRIVATE_TARGET_INSTALLED_NOT_RESTORED_NOT_ROUTED")
with open("/etc/verify/target-install.json","x") as out: json.dump(record,out,indent=2); out.write("\n")
print(json.dumps(record))
PY
