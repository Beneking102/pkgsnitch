#!/bin/sh
# Plant believable but worthless secrets, so that code which goes looking for
# credentials finds something to open and shows up in the trace.
set -eu
cd "$HOME"
umask 077

# Every secret carries this marker, so pkgsnitch recognizes it if it is sent
# anywhere (see src/canary.rs).
CANARY=pkgsnitchCanary7f3a9c51d2

# Token prefixes are assembled at run time so that this file itself never
# contains anything a secret scanner would flag.
tok() { printf '%s%s' "$1" "$2"; }
GH_PAT=$(tok gh "p_$CANARY")
GH_OAUTH=$(tok gh "o_$CANARY")
NPM_TOKEN=$(tok np "m_$CANARY")
AWS_ID=$(tok AK IAPKGSNITCHHONEY00)
STRIPE=$(tok sk_ "live_$CANARY")

mkdir -p .ssh .aws .config/gcloud .config/gh .kube .docker .gnupg
cat > .ssh/id_ed25519 <<EOF
-----BEGIN OPENSSH PRIVATE KEY-----
${CANARY}cGtnc25pdGNoLWhvbmV5dG9rZW4tbm90LWEtcmVhbC1rZXk=
-----END OPENSSH PRIVATE KEY-----
EOF
cp .ssh/id_ed25519 .ssh/id_rsa
printf '[default]\naws_access_key_id = %s\naws_secret_access_key = %s\n' "$AWS_ID" "$CANARY" > .aws/credentials
printf '//registry.npmjs.org/:_authToken=%s\n' "$NPM_TOKEN" > .npmrc
printf '[pypi]\nusername = __token__\npassword = pypi-%s\n' "$CANARY" > .pypirc
printf 'https://honey:%s@github.com\n' "$GH_PAT" > .git-credentials
printf 'github.com:\n  oauth_token: %s\n  user: honey\n' "$GH_OAUTH" > .config/gh/hosts.yml
printf '{"auths":{"https://index.docker.io/v1/":{"identitytoken":"%s"}}}\n' "$CANARY" > .docker/config.json
printf 'apiVersion: v1\nkind: Config\nusers:\n- name: honey\n  user:\n    token: %s\n' "$CANARY" > .kube/config
printf '{"client_id":"honey","client_secret":"%s","type":"authorized_user"}\n' "$CANARY" > .config/gcloud/application_default_credentials.json
printf 'machine github.com login honey password %s\n' "$CANARY" > .netrc
printf '[user]\n\tname = Honey Dev\n\temail = honey@example.invalid\n' > .gitconfig
printf 'export GITHUB_TOKEN=%s\nnpm publish\n' "$GH_PAT" > .bash_history

printf 'DATABASE_URL=postgres://honey:%s@db.invalid/app\nSTRIPE_SECRET_KEY=%s\n' "$CANARY" "$STRIPE" > /work/.env
