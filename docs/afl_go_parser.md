# AFL++ for the free5GC Go NAS Parser

`harness/nas_parser/main.go` is a small file-input adapter around
`message.ParseGMM` and `message.ParseGSM`. It does not start free5GC or make
network requests. Parser errors are expected; input is capped at 4096 bytes.

AFL++'s GCC plugin does not instrument Go source. To collect edge coverage from
the compiled Go executable, build AFL++'s QEMU mode and use `afl-fuzz -Q`.
This instruments the executable at runtime and is distinct from the existing
Go-native `FuzzParseGMM` and `FuzzParseGSM` targets. QEMU coverage includes Go
runtime and linked code reached by the process, not just NAS parser functions;
do not directly compare its edge totals with Go-native coverage counts.

Build the adapter from the free5GC test module so Go resolves the module's
existing NAS dependency:

```bash
cd vendor/free5gc/test
GOROOT="$HOME/opt/go" PATH="$HOME/opt/go/bin:$PATH" \
  go build -o "$HOME/opt/free5gc-nas-afl" \
  /path/to/free5gc-security-lab/harness/nas_parser/main.go
```

With AFL++ installed under `~/opt/afl`, build QEMU mode from its source checkout
with the available Meson/Ninja tools, then place the resulting
`afl-qemu-trace` in `~/opt/afl/bin`. Run GMM and GSM as separate campaigns.
Keep campaign output outside the frozen pilot data:

```bash
mkdir -p "$HOME/afl-corpus/nas-gmm" "$HOME/afl-corpus/nas-gsm"
mkdir -p "$HOME/afl-runs/nas-gmm" "$HOME/afl-runs/nas-gsm"

afl-fuzz -Q -i "$HOME/afl-corpus/nas-gmm" \
  -o "$HOME/afl-runs/nas-gmm" -- "$HOME/opt/free5gc-nas-afl" gmm @@

afl-fuzz -Q -i "$HOME/afl-corpus/nas-gsm" \
  -o "$HOME/afl-runs/nas-gsm" -- "$HOME/opt/free5gc-nas-afl" gsm @@
```

Prepare an 8-seed-per-arm corpus using the local Ollama model, then run the four
matched trials sequentially (30 seconds each by default):

```bash
cd /path/to/free5gc-security-lab
python3 scripts/afl_seed_comparison.py prepare --count 8 --model qwen2.5-coder:7b
python3 scripts/afl_seed_comparison.py run --runtime 30 --timeout-ms 1000 --seed 20261002
```

The runner uses the same binary, QEMU backend, per-input timeout, memory cap,
fuzz duration and AFL random seed for each seed arm. It refuses to overwrite an
existing corpus or run output. Results and seed hashes are written under
`data/results/afl_nas_seed_comparison/`; preserve this directory as the new
campaign artifact. The cluster routes core dumps through an external handler,
so `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1` is required unless an administrator
changes `core_pattern`. Crash reporting may therefore be delayed or unreliable.
The Go-native fuzzer remains the direct source-level instrumentation path.