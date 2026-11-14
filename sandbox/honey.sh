#!/bin/sh
# Plant believable but worthless secrets, so that code which goes looking for
# credentials finds something to open and shows up in the trace.
set -eu
cd "$HOME"
umask 077

# Token prefixes are assembled at run time so that this file itself never
# contains anything a secret scanner would flag.
tok() { printf '%s%s' "$1" "$2"; }
GH_PAT=$(tok gh p_pkgsnitchHoneytokenNotARealToken00000)
GH_OAUTH=$(tok gh o_pkgsnitchHoneytokenNotARealToken0000)
NPM_TOKEN=$(tok np m_pkgsnitchHoneytokenNotARealToken0000)
AWS_ID=$(tok AK IAPKGSNITCHHONEY00)
STRIPE=$(tok sk_ live_pkgsnitchHoneytoken)

mkdir -p .ssh .aws .config/gcloud .config/gh .kube .docker .gnupg
cat > .ssh/id_ed25519 <<'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
cGtnc25pdGNoLWhvbmV5dG9rZW4tbm90LWEtcmVhbC1rZXktZG8tbm90LXVzZQ==
-----END OPENSSH PRIVATE KEY-----
EOF
cp .ssh/id_ed25519 .ssh/id_rsa
printf '[default]\naws_access_key_id = %s\naws_secret_access_key = pkgsnitch/honeytoken/not/a/real/secret/key0\n' "$AWS_ID" > .aws/credentials
printf '//registry.npmjs.org/:_authToken=%s\n' "$NPM_TOKEN" > .npmrc
printf 'https://honey:%s@github.com\n' "$GH_PAT" > .git-credentials
printf 'github.com:\n  oauth_token: %s\n  user: honey\n' "$GH_OAUTH" > .config/gh/hosts.yml
printf '{"auths":{"https://index.docker.io/v1/":{"auth":"aG9uZXk6cGtnc25pdGNo"}}}\n' > .docker/config.json
printf 'apiVersion: v1\nkind: Config\nusers:\n- name: honey\n  user:\n    token: pkgsnitch-honeytoken\n' > .kube/config
printf '{"client_id":"honey","client_secret":"pkgsnitch-honeytoken","type":"authorized_user"}\n' > .config/gcloud/application_default_credentials.json
printf 'machine github.com login honey password pkgsnitch-honeytoken\n' > .netrc
printf '[user]\n\tname = Honey Dev\n\temail = honey@example.invalid\n' > .gitconfig
printf 'export GITHUB_TOKEN=%s\nnpm publish\n' "$GH_PAT" > .bash_history

printf 'DATABASE_URL=postgres://honey:pkgsnitch-honeytoken@db.invalid/app\nSTRIPE_SECRET_KEY=%s\n' "$STRIPE" > /work/.env
