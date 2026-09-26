#!/bin/sh
# Installs every OSINT tool into its own virtualenv under $TOOLS_DIR and links
# its entrypoint into $TOOLS_DIR/bin. Tools are never imported by the app, only
# executed, and separate venvs stop their dependency pins colliding.
#
# This file is the pinned tool manifest: bump versions here.
set -eu

TOOLS_DIR="${TOOLS_DIR:-/opt/tools}"
PYTHON="${PYTHON:-python3}"
AMASS_VERSION="v3.23.3"
# v4.0 tag pins pyyaml<6, which no longer builds; this later commit relaxes it.
SPIDERFOOT_COMMIT="0f815a203afebf05c98b605dba5cf0475a0ee5fd"
THEHARVESTER_VERSION="4.8.0"  # newest release that supports Python 3.11

mkdir -p "$TOOLS_DIR/bin" "$TOOLS_DIR/src"

venv() {
  name="$1"; shift
  "$PYTHON" -m venv "$TOOLS_DIR/$name"
  "$TOOLS_DIR/$name/bin/pip" install --quiet --no-cache-dir --upgrade pip setuptools wheel
  "$TOOLS_DIR/$name/bin/pip" install --quiet --no-cache-dir "$@"
}

link() { ln -sf "$TOOLS_DIR/$1/bin/$2" "$TOOLS_DIR/bin/$2"; }

venv sherlock "sherlock-project==0.16.2" && link sherlock sherlock
venv maigret "maigret==0.6.6" && link maigret maigret
venv holehe "holehe==1.61" && link holehe holehe
venv h8mail "h8mail==2.5.6" && link h8mail h8mail
# Not the PyPI "theHarvester" (an unrelated 0.0.1 placeholder): install the
# upstream tag. pycares 5 breaks the aiodns version this release pins.
venv theharvester "theHarvester @ git+https://github.com/laramies/theHarvester@${THEHARVESTER_VERSION}" "pycares<5"
link theharvester theHarvester

# SpiderFoot isn't packaged: pinned commit + its own requirements + a wrapper.
rm -rf "$TOOLS_DIR/src/spiderfoot"
git init --quiet "$TOOLS_DIR/src/spiderfoot"
git -C "$TOOLS_DIR/src/spiderfoot" fetch --quiet --depth 1 https://github.com/smicallef/spiderfoot "$SPIDERFOOT_COMMIT"
git -C "$TOOLS_DIR/src/spiderfoot" -c advice.detachedHead=false checkout --quiet FETCH_HEAD
rm -rf "$TOOLS_DIR/src/spiderfoot/.git"
venv spiderfoot -r "$TOOLS_DIR/src/spiderfoot/requirements.txt"
cat > "$TOOLS_DIR/bin/spiderfoot" <<WRAPPER
#!/bin/sh
exec "$TOOLS_DIR/spiderfoot/bin/python" "$TOOLS_DIR/src/spiderfoot/sf.py" "\$@"
WRAPPER
chmod 755 "$TOOLS_DIR/bin/spiderfoot"

# Amass: static Go binary, verified against the release's published checksums.
case "$(uname -m)" in
  x86_64|amd64) AMASS_ARCH=amd64; AMASS_SHA256=2b5afb8a567d9703dfb416099fb0452e2b4b4da5170f0b23cd3b812df2e9319c ;;
  aarch64|arm64) AMASS_ARCH=arm64; AMASS_SHA256=b67dfdf5659268bb48626ef39bf9c2c74c0b5d34d21c232a17e07ba200be11b5 ;;
  *) echo "unsupported architecture for amass: $(uname -m)" >&2; exit 1 ;;
esac
tmp="$(mktemp -d)"
curl -fsSL -o "$tmp/amass.zip" \
  "https://github.com/owasp-amass/amass/releases/download/${AMASS_VERSION}/amass_Linux_${AMASS_ARCH}.zip"
echo "$AMASS_SHA256  $tmp/amass.zip" | sha256sum -c -
unzip -q -j "$tmp/amass.zip" "amass_Linux_${AMASS_ARCH}/amass" -d "$TOOLS_DIR/bin"
chmod 755 "$TOOLS_DIR/bin/amass"
rm -rf "$tmp"

echo "Installed tools into $TOOLS_DIR/bin:"
ls "$TOOLS_DIR/bin"
