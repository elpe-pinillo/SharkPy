# Contributing to SharkPy

Thank you for taking the time to contribute. SharkPy is a community-maintained security tool and all contributions — bug reports, feature requests, documentation improvements, and code — are welcome.

---

## Code of Conduct

Be respectful and constructive. This project is used by security professionals and researchers. Discriminatory language, personal attacks, and off-topic behaviour will result in your contribution being closed without review.

---

## Reporting Bugs

Before opening an issue, search the [existing issues](../../issues) to avoid duplicates.

When you file a bug report, use the **Bug Report** issue template and include:

- Your OS, Python version, and SharkPy version
- The capture mode in use (Intercept / Sniff / TLS)
- The full traceback or relevant log output
- Minimal steps to reproduce the problem

The more concrete the reproduction steps, the faster the fix.

---

## Suggesting Features

Use the **Feature Request** issue template. Describe:

- The problem you're trying to solve (not just the proposed solution)
- How this fits SharkPy's scope (packet capture / manipulation / TLS MITM)
- Whether you're willing to implement it yourself

Features that require root / admin privilege should document that requirement clearly.

---

## Development Setup

```bash
# 1. Fork and clone
git clone https://github.com/YourUser/SharkPy.git
cd SharkPy

# 2. Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3. Install in editable mode with dev extras
pip install -e .
pip install flake8 pyflakes

# 4. Run the app
#    SharkPy reads from the network and modifies iptables — root is required
#    for intercept and TLS modes; sniff mode works without it on some systems.
cd Sharkpy
sudo python3 main.py             # Linux
python main.py                   # Windows (admin terminal)
```

All source files live under `Sharkpy/`. The working directory when running directly should be `Sharkpy/` so that bare imports (`from core import ...`, `from gui import ...`) resolve correctly. When installed via `pip install -e .`, the `sharkpy` console entry point handles this automatically.

---

## Code Style

- Follow **PEP 8**. Line length limit is **120 characters** (the flake8 config in `pyproject.toml` enforces this).
- Use meaningful names. Single-letter variables are acceptable only as loop counters or in mathematical contexts.
- Keep **Qt widget names stable**. The UI definitions in `gui/qt_ui.py` define widget attribute names that `main.py` references directly. Renaming a widget attribute is a breaking change; always check all references before doing so.
- Add **docstrings** to all public functions and classes (Google or NumPy style, either is fine).
- Do not block the **Qt main thread**. Any I/O or computation that takes more than ~50 ms must run in a background thread. Use `QMetaObject.invokeMethod` with `Qt.QueuedConnection` or a `pyqtSignal` to communicate results back to the GUI.
- All **UI widget creation** belongs in `gui/qt_ui.py`. Event handler logic belongs in `main.py`. Do not create new widgets inside `main.py`.

---

## Pull Request Process

1. **Fork** the repository and create a feature branch from `main`:
   ```bash
   git checkout -b fix/describe-your-fix
   # or
   git checkout -b feature/describe-your-feature
   ```

2. **Make your changes** and commit with clear messages:
   ```bash
   git commit -m "fix: resolve NFQUEUE crash when interface is removed mid-capture"
   ```

3. **Run the linter** before pushing:
   ```bash
   flake8 Sharkpy/ --max-line-length=120 \
     --exclude=Sharkpy/gui/qt_ui.py,Sharkpy/auxiliar.py
   ```

4. **Update CHANGELOG.md** — add your change under `[Unreleased]`.

5. **Open a Pull Request** against the `main` branch. Fill in the PR template. A maintainer will review within a reasonable timeframe.

6. Address review feedback in new commits (do not force-push to an open PR branch unless asked to).

---

## Architecture Notes

Understanding the threading model will prevent common mistakes:

- **Qt main thread** — all widget access must happen here. Never read or write widget state from a background thread.
- **CoreClass (capture thread)** — runs `NFQUEUE.run()`, `AsyncSniffer`, or the WinDivert loop. Pushes packets to the GUI via `QMetaObject.invokeMethod(..., Qt.QueuedConnection, ...)`. The `push_packets` slot in `main.py` receives these and updates the table.
- **TLSProxy threads** — one accept thread plus one pair of relay threads per active TLS connection. Data is surfaced to the GUI via the `data_intercepted` pyqtSignal, which PyQt5 automatically queues for delivery on the main thread.

When adding a new feature that involves background work:

- Define a `pyqtSignal` on the relevant `QObject` subclass for any data the thread needs to pass back.
- Connect the signal to a slot in `main.py` (or wherever the UI update lives) using the default `AutoConnection` — PyQt5 will queue the delivery correctly.
- Never access `self.parent.<widget>` directly from a non-main thread.
