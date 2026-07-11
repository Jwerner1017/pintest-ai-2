"""Generate one-click launch artifacts for security distros.

Each distro returns a self-contained bash script the user can `curl | bash` to spin up
the distro (Docker where available, ISO instructions where not) with the scan target
pre-populated as an env var so they can resume the engagement instantly.
"""
from datetime import datetime, timezone


def build_launch_script(distro_id: str, target: str, scan_id: str | None) -> tuple[str, str]:
    """Return (script_text, filename) for the given distro + target."""
    target = _sanitize(target) or "example.com"
    scan_id = _sanitize(scan_id or "")
    builder = _BUILDERS.get(distro_id)
    if not builder:
        raise KeyError(distro_id)
    return builder(target, scan_id)


def _sanitize(s: str) -> str:
    """Strip CR/LF and other control chars so values cannot break out of bash
    comments or env-export single-quotes. Allows printable ASCII + common
    punctuation only."""
    if not s:
        return ""
    # Drop CR/LF/tab and any non-printable / high-bit chars.
    return "".join(c for c in s if 32 <= ord(c) < 127 and c not in "\r\n").strip()


def _preamble(distro_name: str, target: str, scan_id: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""#!/usr/bin/env bash
# ============================================================================
# PentestAI -> {distro_name} launch script
# Generated: {ts}
# Target:   {target}
# Scan ID:  {scan_id or 'n/a'}
# ----------------------------------------------------------------------------
# This script bootstraps a {distro_name} environment pre-loaded with your
# PentestAI scan context. Run on a host with Docker (where supported) or
# follow the printed instructions for ISO / live-USB workflows.
# ============================================================================
set -e
export PENTESTAI_TARGET={_shell_quote(target)}
export PENTESTAI_SCAN_ID={_shell_quote(scan_id)}
echo "[PentestAI] target=$PENTESTAI_TARGET  scan_id=$PENTESTAI_SCAN_ID"
"""


def _shell_quote(s: str) -> str:
    """Single-quote escape for safe interpolation into bash env-export lines.

    Values must be pre-sanitised by _sanitize() to remove CR/LF and non-printable
    chars; this function then wraps the remaining printable ASCII in single quotes
    and escapes embedded single quotes via the standard '\\'' pattern.
    """
    safe = s.replace("'", "'\\''")
    return f"'{safe}'"


def _backbox(target: str, scan_id: str) -> tuple[str, str]:
    script = _preamble("BackBox", target, scan_id) + """
# ----- BackBox via Docker --------------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  echo "[error] Docker is required. Install: https://docs.docker.com/engine/install/"
  exit 1
fi

WORKDIR="${HOME}/pentestai-backbox"
mkdir -p "$WORKDIR"
cat > "$WORKDIR/target.env" <<EOF
PENTESTAI_TARGET=$PENTESTAI_TARGET
PENTESTAI_SCAN_ID=$PENTESTAI_SCAN_ID
EOF

cat > "$WORKDIR/.bash_profile" <<'EOF'
echo ""
echo "=========================================="
echo "  PentestAI -> BackBox"
echo "  Target: $PENTESTAI_TARGET"
echo "=========================================="
echo "Quick commands:"
echo "  nmap -A $PENTESTAI_TARGET"
echo "  nikto -h $PENTESTAI_TARGET"
echo "  zap-cli quick-scan $PENTESTAI_TARGET"
echo "  sqlmap -u 'http://$PENTESTAI_TARGET' --batch"
echo ""
EOF

echo "[PentestAI] Pulling BackBox image (first run ~600MB)..."
docker pull backbox/backbox:latest || true

echo "[PentestAI] Launching interactive BackBox shell..."
exec docker run --rm -it \\
  --hostname backbox \\
  -e PENTESTAI_TARGET \\
  -e PENTESTAI_SCAN_ID \\
  -v "$WORKDIR":/pentestai \\
  -v "$WORKDIR/.bash_profile":/root/.bash_profile \\
  backbox/backbox:latest /bin/bash --login
"""
    return script, f"launch-backbox-{_slug(target)}.sh"


def _pentoo(target: str, scan_id: str) -> tuple[str, str]:
    script = _preamble("Pentoo", target, scan_id) + """
# ----- Pentoo via Docker (gentoo-based) ------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  echo "[warn] Docker not found. ISO download: https://www.pentoo.ch/downloads/"
  echo "Boot the ISO in a VM (KVM recommended for GPU passthrough):"
  echo "  qemu-system-x86_64 -m 8192 -smp 4 -boot d -cdrom pentoo.iso -enable-kvm"
  exit 0
fi

echo "[PentestAI] Pentoo official image is community-maintained; using gentoo/stage3 + pentoo overlay..."
WORKDIR="${HOME}/pentestai-pentoo"
mkdir -p "$WORKDIR"

# Pentoo's strength is GPU password cracking + wireless tooling. Inside the
# container we install hashcat & aircrack-ng on top of the gentoo base.
docker run --rm -it \\
  --hostname pentoo \\
  -e PENTESTAI_TARGET \\
  -e PENTESTAI_SCAN_ID \\
  -v "$WORKDIR":/pentestai \\
  gentoo/stage3:latest /bin/bash -c '
    echo "[PentestAI] Pentoo shell ready. Target: $PENTESTAI_TARGET"
    echo "Suggested workflow:"
    echo "  emerge -av hashcat aircrack-ng nmap"
    echo "  hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt"
    /bin/bash
  '
"""
    return script, f"launch-pentoo-{_slug(target)}.sh"


def _deft(target: str, scan_id: str) -> tuple[str, str]:
    script = _preamble("DEFT Linux", target, scan_id) + """
# ----- DEFT (Digital Evidence & Forensic Toolkit) --------------------------
# DEFT is forensics-focused. Best run from USB live media to preserve a clean
# chain of custody. Docker is NOT recommended for evidence work.

cat <<EOF

[PentestAI] DEFT is best used live-boot to preserve evidence integrity.

1) Download ISO:
   https://archive.org/details/deft-linux  (mirror of historical builds)
   For modern Tsurugi Linux successor: https://tsurugi-linux.org

2) Write to USB (Linux/macOS):
   sudo dd if=deft.iso of=/dev/sdX bs=4M status=progress oflag=sync

3) Boot target machine from USB and acquire evidence.

4) Scan context to copy onto your evidence note:
   Target:  $PENTESTAI_TARGET
   Scan:    $PENTESTAI_SCAN_ID

For non-evidentiary triage, a quick VM is acceptable:
   qemu-system-x86_64 -m 4096 -boot d -cdrom deft.iso -enable-kvm

Recommended tools inside DEFT once booted:
   dc3dd if=/dev/sdb of=/mnt/evidence/disk.dd hash=sha256
   volatility -f mem.dmp imageinfo
   autopsy &

EOF
"""
    return script, f"launch-deft-{_slug(target)}.sh"


def _kodachi(target: str, scan_id: str) -> tuple[str, str]:
    script = _preamble("Linux Kodachi", target, scan_id) + """
# ----- Linux Kodachi (privacy / OPSEC) --------------------------------------
# Kodachi is anti-forensic and live-boot only. Designed to leave no trace.

cat <<EOF

[PentestAI] Kodachi is a live-only privacy OS. NEVER install it persistently
on disk if your goal is anti-forensic OPSEC — every boot starts fresh.

1) Download ISO:
   https://www.digi77.com/linux-kodachi/

2) Verify signature (paranoia mode):
   gpg --verify kodachi.iso.sig kodachi.iso

3) Live boot from USB:
   sudo dd if=kodachi.iso of=/dev/sdX bs=4M status=progress oflag=sync

4) QUICK VM (NOT recommended for real OPSEC — VMs leak host fingerprints):
   qemu-system-x86_64 -m 4096 -boot d -cdrom kodachi.iso -enable-kvm \\
     -netdev user,id=net0,restrict=on -device virtio-net,netdev=net0

5) Once booted, Tor + DNSCrypt + VPN chain are active by default.
   Your re-reconnaissance target ($PENTESTAI_TARGET) can be re-scanned with:
       proxychains nmap -sT -Pn $PENTESTAI_TARGET
       torify whois $PENTESTAI_TARGET

Scan context preserved (paste into Kodachi's KeePassXC):
   Target:  $PENTESTAI_TARGET
   Scan:    $PENTESTAI_SCAN_ID

EOF
"""
    return script, f"launch-kodachi-{_slug(target)}.sh"


def _slug(s: str) -> str:
    out = "".join(c if c.isalnum() else "-" for c in s)[:40].strip("-")
    return out or "target"


_BUILDERS = {
    "backbox": _backbox,
    "pentoo": _pentoo,
    "deft": _deft,
    "kodachi": _kodachi,
}
