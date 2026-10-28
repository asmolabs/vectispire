#!/bin/sh
# Prepares the forge, then runs sshd and the HTTPS server. Everything secret here is made at start and
# lives only in this container.
set -eu

mkdir -p /certs /keys
cd /certs
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' > server.ext
openssl ecparam -name prime256v1 -genkey -noout -out ca.key 2>/dev/null
openssl req -new -x509 -key ca.key -days 2 -subj "/CN=vs-rs test authority" \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign -out ca.pem
openssl ecparam -name prime256v1 -genkey -noout -out server.key 2>/dev/null
openssl req -new -key server.key -subj "/CN=localhost" -out server.csr 2>/dev/null
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile server.ext -out server.pem 2>/dev/null

# SSH: one host key type, so the tests pin exactly what the server offers.
rm -f /etc/ssh/ssh_host_*
ssh-keygen -q -t ed25519 -N "" -f /etc/ssh/ssh_host_ed25519_key
ssh-keygen -q -t ed25519 -N "" -C deploy -f /keys/deploy
ssh-keygen -q -t ed25519 -N "" -C other -f /keys/other
# The other key types a deployment key comes in, OpenSSH-encoded and PEM (PKCS#1) for RSA.
ssh-keygen -q -t rsa -b 3072 -N "" -C rsa -f /keys/rsa
ssh-keygen -q -t ecdsa -b 256 -N "" -C ecdsa -f /keys/ecdsa
cp /keys/rsa /keys/rsa-pem && ssh-keygen -q -p -N "" -m PEM -f /keys/rsa-pem
adduser -D -h /home/git -s /usr/bin/git-shell git
echo 'git:*' | chpasswd -e
mkdir -p /home/git/.ssh
cat /keys/deploy.pub /keys/rsa.pub /keys/ecdsa.pub > /home/git/.ssh/authorized_keys
chown -R git:git /home/git && chmod 700 /home/git/.ssh && chmod 600 /home/git/.ssh/authorized_keys
cat > /etc/ssh/sshd_config <<'CONFIG'
Port 22
HostKey /etc/ssh/ssh_host_ed25519_key
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AllowUsers git
PermitRootLogin no
CONFIG

# The repository: `main` and `feature`, under /srv/git/team/api.git, also served at /public/.
mkdir -p /srv/git/team /srv/work
git -C /srv/work init -q -b main
printf 'a tree to scan\n' > /srv/work/README.md
git -C /srv/work -c user.name=forge -c user.email=forge@example.org add README.md
git -C /srv/work -c user.name=forge -c user.email=forge@example.org commit -q -m first
git -C /srv/work branch feature
git clone -q --bare /srv/work /srv/git/team/api.git
git -C /srv/git/team/api.git config http.receivepack false
chown -R git:git /srv/git
# http-backend runs as root here, on repositories git owns.
git config --system --add safe.directory '*'

/usr/sbin/sshd -E /tmp/sshd.log
touch /tmp/requests.log && chmod 666 /tmp/requests.log
touch /certs/ready
exec python3 /forge/https_forge.py
