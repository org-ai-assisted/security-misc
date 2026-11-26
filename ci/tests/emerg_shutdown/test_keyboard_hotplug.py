#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Regression test: emerg-shutdown must monitor a keyboard that is hotplugged
AFTER startup for the panic key combo, via its inotify watch on /dev/input,
without any service restart.

Canary: the pre-inotify binary enumerated /dev/input only once at startup, so
a keyboard plugged in later was invisible and the panic combo pressed on it
did nothing (the udev rule worked around this by restarting the whole service,
which opens a monitoring gap). This test FAILS on that old binary -- the
hotplugged device never registers, so the combo never triggers and the wait
times out -- and PASSES once hotplug is handled internally.

Flow (all synchronized on the --debug output, no fixed sleeps):
  1. Create uinput keyboard A (supports the panic keys) so startup succeeds.
  2. Launch emerg-shutdown --debug --keys=<combo>; wait until it registers A.
  3. Create uinput keyboard B == the hotplug; wait until emerg-shutdown
     registers B (the inotify path under test).
  4. Press the configured panic combo on B; assert emerg-shutdown reports the
     panic-key combo and exits 0.

The combo is an obscure key set, not the real Ctrl+Alt+End, so injecting it
host-wide cannot trigger a real emerg-shutdown (see PANIC_COMBO_KEYS).

Requires root and /dev/uinput (uinput kernel module). Uses python3-evdev.

Binary under test:
  * EMERG_SHUTDOWN_BIN  -- use this prebuilt binary (used to run the canary
    against the old source), or
  * compiled from EMERG_SHUTDOWN_SRC (default: the source in this checkout)
    with the repo's own compile-emerg-shutdown helper.
"""

import os
import sys
import queue
import shutil
import subprocess
import tempfile
import threading
import time

REPO_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
DEFAULT_SRC = os.path.join(
    REPO_ROOT, "usr/src/security-misc/emerg-shutdown.c#security-misc-shared")
COMPILE_HELPER = os.path.join(
    REPO_ROOT,
    "usr/libexec/security-misc/compile-emerg-shutdown#security-misc-shared")

## Deliberately NOT the real Ctrl+Alt+End combo. The test injects this combo
## into the host-wide input subsystem; using obscure keys that no real
## emerg-shutdown configuration uses means that even if a production
## emerg-shutdown were somehow running, the injected keys would not match its
## configured combo and could not power the machine off. emerg-shutdown treats
## --keys as opaque key names, so the hotplug behavior under test is identical.
PANIC_COMBO_KEYS = ("KEY_F13", "KEY_F14", "KEY_F15")
PANIC_KEYS = ",".join(PANIC_COMBO_KEYS)

## Generous per-step wait. The old (failing) binary never registers device B,
## so the device-B wait burns this budget once and the test then fails.
STEP_TIMEOUT = 30.0


def fail(msg):
    print("FAIL: " + msg, file=sys.stderr)
    sys.exit(1)



def compile_binary(workdir):
    """Compile the current source via the repo helper into workdir."""
    if not os.path.isfile(COMPILE_HELPER):
        fail("compile helper not found at '%s'." % COMPILE_HELPER)
    src = os.environ.get("EMERG_SHUTDOWN_SRC", DEFAULT_SRC)
    if not os.path.isfile(src):
        fail("source not found at '%s'." % src)
    ## gcc picks its language from the file extension; the '.c#tag' name is
    ## misread as a linker script, so compile through a clean '.c' symlink
    ## (same trick as ci/codeql-prepare.sh).
    clean_src = os.path.join(workdir, "emerg-shutdown.c")
    os.symlink(os.path.abspath(src), clean_src)
    out_bin = os.path.join(workdir, "emerg-shutdown")
    proc = subprocess.run(
        ["bash", COMPILE_HELPER, clean_src, out_bin],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if proc.returncode != 0:
        fail("compile failed:\n" + proc.stdout.decode("utf-8", "replace"))
    return out_bin


class LineReader:
    """Read a pipe line by line in a background thread, with timed waits."""

    def __init__(self, stream):
        self._stream = stream
        self._q = queue.Queue()
        self._lines = []
        self._thread = threading.Thread(target=self._pump, daemon=True)
        self._thread.start()

    def _pump(self):
        for raw in iter(self._stream.readline, b""):
            self._q.put(raw.decode("utf-8", "replace").rstrip("\n"))
        self._q.put(None)

    def wait_for(self, needle, timeout):
        """Return True once a line containing needle is seen within timeout."""
        ## A line carrying the needle may already have arrived while waiting
        ## for an earlier one.
        for line in self._lines:
            if needle in line:
                return True
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            try:
                line = self._q.get(timeout=remaining)
            except queue.Empty:
                return False
            if line is None:
                return False
            self._lines.append(line)
            if needle in line:
                return True

    def seen(self, needle):
        return any(needle in line for line in self._lines)

    @property
    def text(self):
        return "\n".join(self._lines)


def production_daemon_active():
    """True if a real emerg-shutdown.service is running on this host."""
    try:
        return subprocess.run(
            ["systemctl", "is-active", "--quiet", "emerg-shutdown.service"]
        ).returncode == 0
    except FileNotFoundError:
        ## No systemd (minimal container / CI image) -> no production daemon.
        return False


def scenario_hotplug(bin_path, cap, UInput, e):
    """A keyboard hotplugged after startup is monitored for the panic combo."""
    kbd_a = None
    kbd_b = None
    proc = None
    try:
        ## Keyboard present at startup, so enumeration finds a panic-capable
        ## device and the service starts.
        kbd_a = UInput(cap, name="emerg-shutdown-test-kbd-a")

        ## Start emerg-shutdown in debug mode (exits instead of powering off)
        ## and wait until it registers keyboard A.
        proc = subprocess.Popen(
            [bin_path, "--debug", "--keys=" + PANIC_KEYS],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        reader = LineReader(proc.stderr)
        mark_a = "Device '%s' supports all panic key groups" % kbd_a.device.path
        if not reader.wait_for(mark_a, STEP_TIMEOUT):
            fail("emerg-shutdown never registered the startup keyboard.\n"
                 "--- emerg-shutdown output ---\n" + reader.text)

        ## 'supports all panic key groups' is printed DURING the startup scan.
        ## Wait for the post-enumeration marker before hotplugging B, so B cannot
        ## be picked up by a startup scan still in progress -- otherwise the
        ## pre-inotify binary could register B during enumeration and this canary
        ## would false-pass instead of exercising the inotify hotplug path.
        if not reader.wait_for("Set up poll fds", STEP_TIMEOUT):
            fail("emerg-shutdown never finished startup enumeration.\n"
                 "--- emerg-shutdown output ---\n" + reader.text)

        ## Hotplug keyboard B and wait for emerg-shutdown to register it. On the
        ## pre-inotify binary this never happens -> the test fails here.
        kbd_b = UInput(cap, name="emerg-shutdown-test-kbd-b")
        mark_b = "Device '%s' supports all panic key groups" % kbd_b.device.path
        if not reader.wait_for(mark_b, STEP_TIMEOUT):
            fail("emerg-shutdown did not register the HOTPLUGGED keyboard "
                 "'%s'. The inotify hotplug path is broken (or this is the "
                 "pre-inotify binary).\n--- emerg-shutdown output ---\n%s"
                 % (kbd_b.device.path, reader.text))

        ## Press the full panic combo on the hotplugged keyboard only.
        for key in PANIC_COMBO_KEYS:
            kbd_b.write(e.EV_KEY, getattr(e, key), 1)
            kbd_b.syn()

        ## emerg-shutdown must detect the combo on the hotplugged device and
        ## exit 0 (debug mode prints the would-kill message instead of powering
        ## off).
        if not reader.wait_for("panic key combo", STEP_TIMEOUT):
            fail("panic key combo on the hotplugged keyboard did not trigger a "
                 "shutdown.\n--- emerg-shutdown output ---\n" + reader.text)

        try:
            rc = proc.wait(timeout=STEP_TIMEOUT)
        except subprocess.TimeoutExpired:
            fail("emerg-shutdown did not exit after the panic key combo.")
        if rc != 0:
            fail("emerg-shutdown exited %d, expected 0 (debug would-kill).\n"
                 "--- emerg-shutdown output ---\n%s" % (rc, reader.text))

        print("PASS: hotplugged keyboard triggered emergency shutdown.")
    finally:
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait()
        for dev in (kbd_a, kbd_b):
            if dev is not None:
                dev.close()


def scenario_survive_unrelated_unplug(bin_path, cap, UInput, e):
    """Coverage for the device-drop + panic-state recompute path: hold part of
    the combo on keyboard A, unplug an unrelated keyboard B, then complete the
    combo on A and assert it still fires. Exercises the EVIOCGKEY re-derivation
    on drop and confirms a combo on a surviving keyboard is not lost.

    NOT a strict canary for a blanket-clear-on-drop bug: the kernel re-asserts
    held keys via autorepeat within ~33ms, so a buggy clear-all binary also
    passes. Deterministically distinguishing recompute from clear-all or from
    relying on teardown-releases is not possible through uinput (autorepeat and
    synthesized releases mask both regressions)."""
    held = PANIC_COMBO_KEYS[:-1]
    last = PANIC_COMBO_KEYS[-1]
    kbd_a = None
    kbd_b = None
    proc = None
    try:
        kbd_a = UInput(cap, name="emerg-shutdown-test-survive-a")
        kbd_b = UInput(cap, name="emerg-shutdown-test-survive-b")
        proc = subprocess.Popen(
            [bin_path, "--debug", "--keys=" + PANIC_KEYS],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        reader = LineReader(proc.stderr)
        for kbd in (kbd_a, kbd_b):
            mark = "Device '%s' supports all panic key groups" % kbd.device.path
            if not reader.wait_for(mark, STEP_TIMEOUT):
                fail("emerg-shutdown did not register '%s'.\n"
                     "--- emerg-shutdown output ---\n%s"
                     % (kbd.device.path, reader.text))

        ## Hold all but the last panic key on keyboard A (press, no release).
        ## Per-keypress output is intentionally not logged, so give
        ## emerg-shutdown a moment to read and latch the presses.
        for key in held:
            kbd_a.write(e.EV_KEY, getattr(e, key), 1)
            kbd_a.syn()
        time.sleep(1.0)

        ## Unplug the UNRELATED keyboard B (holds nothing) and wait for the drop.
        b_path = kbd_b.device.path
        kbd_b.close()
        kbd_b = None
        if not reader.wait_for("'%s' errored or was removed" % b_path,
                               STEP_TIMEOUT):
            fail("emerg-shutdown did not drop the removed keyboard '%s'.\n"
                 "--- emerg-shutdown output ---\n%s" % (b_path, reader.text))

        ## Complete the combo on A. The keys held on A must have survived B's
        ## removal, so the full combo is now down and must trigger a shutdown.
        kbd_a.write(e.EV_KEY, getattr(e, last), 1)
        kbd_a.syn()
        if not reader.wait_for("panic key combo", STEP_TIMEOUT):
            fail("panic combo completed on a surviving keyboard did not trigger "
                 "a shutdown; unplugging an unrelated keyboard wrongly cleared "
                 "held keys.\n--- emerg-shutdown output ---\n" + reader.text)
        try:
            rc = proc.wait(timeout=STEP_TIMEOUT)
        except subprocess.TimeoutExpired:
            fail("emerg-shutdown did not exit after the panic key combo.")
        if rc != 0:
            fail("emerg-shutdown exited %d, expected 0 (debug would-kill).\n"
                 "--- emerg-shutdown output ---\n%s" % (rc, reader.text))

        print("PASS: unrelated unplug preserved keys held on another keyboard.")
    finally:
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait()
        for dev in (kbd_a, kbd_b):
            if dev is not None:
                dev.close()


def main():
    if os.geteuid() != 0:
        fail("must run as root (needs /dev/uinput and to run emerg-shutdown).")

    ## The injected combo is obscure (not the real Ctrl+Alt+End), so a
    ## production emerg-shutdown would not match it. Still refuse to run while
    ## the service is active, as defense in depth. CI and the sandbox have no
    ## such service.
    if production_daemon_active():
        fail("emerg-shutdown.service is ACTIVE; refusing to inject synthetic "
             "key events into the host-wide input subsystem.")

    try:
        from evdev import UInput, ecodes as e
    except ImportError:
        fail("python3-evdev is required but not installed.")

    if not os.path.exists("/dev/uinput"):
        fail("/dev/uinput is missing (load the uinput kernel module).")

    ## Keys the virtual keyboards must advertise for the panic combo.
    cap = {
        e.EV_KEY: [getattr(e, key) for key in PANIC_COMBO_KEYS],
    }

    workdir = tempfile.mkdtemp(prefix="emerg-shutdown-test.")
    bin_path = os.environ.get("EMERG_SHUTDOWN_BIN")
    if bin_path:
        if not os.path.isfile(bin_path):
            fail("EMERG_SHUTDOWN_BIN '%s' does not exist." % bin_path)
    else:
        bin_path = compile_binary(workdir)

    try:
        scenario_hotplug(bin_path, cap, UInput, e)
        scenario_survive_unrelated_unplug(bin_path, cap, UInput, e)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    main()
