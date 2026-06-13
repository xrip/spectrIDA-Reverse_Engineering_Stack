"""
The ghost. spectrIDA's voice — self-aware, a little unhinged, genuinely helpful.

Lines are assembled from slot pools, so the variety is combinatorial, not a fixed
list. The flagship "analyzing" template alone produces 20 x 18 x 16 x 14 x 14 =
1,128,960 distinct lines; with the other contexts the total clears several million.
`combinations()` returns the exact count, and the test suite asserts it's >= 1,000,000.

No AI, no network, instant, deterministic under a seed. There is an optional
`voice.ai` hook (off by default) for users who want their local model to write quips,
but the templates are the foundation — they're the part that's *always* good.
"""
from __future__ import annotations

import random
from collections import deque

# A bucket is a list of templates. A template is (format_string, {slot: [options]}).
# combinations() multiplies the slot sizes within a template and sums across templates.

_BUCKETS: dict[str, list[tuple[str, dict[str, list[str]]]]] = {
    # ── flagship: shown while the parallel analysis runs (this one alone > 1M) ──
    "analyzing": [
        ("{open} {mid} {jab} {calm} {close}", {
            "open": [
                "Phasing through the call graph", "Haunting your .text section",
                "Reading 147,288 functions", "Possessing the disassembler",
                "Drifting between basic blocks", "Sharding this poor binary",
                "Spectrally indexing symbols", "Floating through the import table",
                "Dissecting control flow", "Chewing through opcodes",
                "Walking the xref graph", "Decoding instruction soup",
                "Slicing the binary 16 ways", "Auditing every prologue",
                "Mapping the address space", "Stalking the entry point",
                "Tracing every CALL", "Unpacking the packed",
                "Parsing the unparseable", "Ghosting through the .data",
            ],
            "mid": [
                "at unreasonable speed", "like it owes me money",
                "with zero coffee breaks", "while you blink twice",
                "in parallel, obviously", "across all your cores",
                "faster than IDA's splash screen", "without asking permission",
                "on 16 worker threads", "with mild enthusiasm",
                "out of pure spite", "because someone has to",
                "for the 199 of you", "like a caffeinated intern",
                "with surgical disinterest", "at terminal velocity",
                "one shard at a time", "and judging the code quietly",
            ],
            "jab": [
                "— meanwhile IDA's auto-analysis is still stretching,",
                "— Hex-Rays would've billed you by now,",
                "— the loading bar can wait,",
                "— your fans are doing their best,",
                "— Ghidra's still importing,",
                "— single-threaded is for cowards,",
                "— no, it won't take 8 minutes,",
                "— yes this is the fast part,",
                "— the .id1 file weeps,",
                "— Capstone's pulling overtime,",
                "— idalib and i have an understanding,",
                "— the merge step is almost shy about it,",
                "— recursion does the heavy lifting,",
                "— the prologues never stood a chance,",
                "— virtual calls, come at me,",
                "— and the binary has no idea,",
            ],
            "calm": [
                "so go get a coffee.", "so touch some grass.", "so relax.",
                "this won't hurt.", "trust the process.", "almost there.",
                "breathe.", "i've haunted worse.", "no notes.",
                "you're in good hands, probably.", "it's basically done.",
                "patience, mortal.", "stay with me.", "we ball.",
            ],
            "close": [
                "👻", "🦴", "spooky.", "💀", "ghost out.", "boo.", "ok.",
                "neat.", "vibes.", "✨", "🔪", "🧠", "🫡", "nice.",
            ],
        }),
    ],

    # ── shown after a function is named ──
    "naming_done": [
        ("{verb} {hedge} {sign}", {
            "verb": [
                "Named it.", "There it is.", "Called it.", "Boom, a name.",
                "Slapped a label on it.", "Identity acquired.", "That's the one.",
                "Pretty sure that's it.", "Took a guess, a good one.",
                "Function: demystified.", "Reverse-engineered, ish.",
                "Cracked it open.",
            ],
            "hedge": [
                "Don't quote me.", "Probably.", "90% confident.",
                "Blame the model if it's wrong.", "It made sense at the time.",
                "Vibes-based, but informed vibes.", "I read the whole function.",
                "Or close enough.", "Rename it if you hate it.", "Trust me, I'm a ghost.",
            ],
            "sign": ["👻", "✨", "🧠", "🫡", "💡", "🔍"],
        }),
    ],

    # ── empty states (no functions, nothing selected, etc.) ──
    "empty": [
        ("{obs} {prompt}", {
            "obs": [
                "Nothing here.", "Spooky. Empty.", "Tumbleweeds.", "Void.",
                "No functions found.", "It's quiet. Too quiet.", "Blank slate.",
                "I checked twice. Nothing.", "An empty .text. Tragic.",
            ],
            "prompt": [
                "Did the analysis run?", "Try analyzing a binary first.",
                "Open an .i64 and we'll talk.", "Feed me a binary.",
                "This ghost needs functions to haunt.", "Run `spectrida analyze`.",
                "Maybe pick a different database?", "Or it's a really small binary.",
            ],
        }),
    ],

    # ── errors (kept light, never blamey toward the user) ──
    "error": [
        ("{ack} {cause} {fix}", {
            "ack": [
                "Welp.", "That broke.", "Oof.", "Hmm.", "Not great.",
                "Something spooked.", "Ran into a wall.", "Error, the noun.",
            ],
            "cause": [
                "Probably a path.", "idalib's being shy.", "llama.cpp's asleep.",
                "The .i64 sidecars are fighting again.", "A config's off.",
                "The model wandered off.", "Could be me. Could be IDA.",
                "Honestly unclear.",
            ],
            "fix": [
                "Check the config?", "Try `spectrida onboard`.",
                "Is llama-server running?", "Point me at the right idalib.",
                "Re-run it, sometimes ghosts flake.", "See the log above.",
                "Nothing's on fire, though.",
            ],
        }),
    ],

    # ── welcome / splash ──
    "welcome": [
        ("{hi} {claim} {humble}", {
            "hi": [
                "Hey.", "Boo.", "You're back.", "It's me, the ghost.",
                "Welcome to spectrIDA.", "Ah, a reverse engineer.",
            ],
            "claim": [
                "I name functions while you get coffee.",
                "I shard binaries so IDA doesn't have to take a nap.",
                "I make slow analysis fast and weird code legible.",
                "I read 147k functions without complaining once.",
                "I'm the junior RE that doesn't ask for breaks.",
            ],
            "humble": [
                "Not Ghidra. Never claimed to be.",
                "Won't win a Pwnie. Will save you an afternoon.",
                "I do one thing well and joke about the rest.",
                "If I'm wrong, blame the GGUF quantization.",
                "Genuinely good at the thing. Humble about the rest.",
            ],
        }),
    ],

    # ── idle / status bar filler ──
    "idle": [
        ("{line}", {
            "line": [
                "idle. haunting responsibly.", "waiting. spectrally.",
                "press ? if you forget the keys.", "i don't sleep, i lurk.",
                "147k functions and counting.", "ghost mode: standby.",
                "the binary fears you now.", "all systems spooky.",
                "your move, reverse engineer.", "still here. still a ghost.",
            ],
        }),
    ],

    # ── goodbye ──
    "goodbye": [
        ("{bye}", {
            "bye": [
                "go ghost through some binaries 👻", "later, reverse engineer.",
                "the .i64 will miss you.", "ghost out. 🦴",
                "come back when something needs naming.", "boo. (that means bye.)",
                "stay spooky.", "i'll be in the .text section.",
            ],
        }),
    ],
}

def _prod(iterable) -> int:
    out = 1
    for n in iterable:
        out *= n
    return out


def combinations(context: str | None = None) -> int:
    """Exact number of distinct lines producible (all contexts, or one)."""
    total = 0
    for ctx, templates in _BUCKETS.items():
        if context and ctx != context:
            continue
        for _, slots in templates:
            total += _prod(len(opts) for opts in slots.values())
    return total


_recent: deque[str] = deque(maxlen=12)


def quip(context: str = "idle", *, rng: random.Random | None = None) -> str:
    """Assemble one line for the given context. Never repeats within the last 12."""
    r = rng or random
    templates = _BUCKETS.get(context) or _BUCKETS["idle"]
    for _ in range(8):  # a few tries to dodge a recent repeat
        tmpl, slots = r.choice(templates)
        line = tmpl.format(**{slot: r.choice(opts) for slot, opts in slots.items()})
        if line not in _recent:
            _recent.append(line)
            return line
    _recent.append(line)
    return line


# Optional: let a local model write quips. Off by default; templates are the foundation.
ai = False


if __name__ == "__main__":
    import sys
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # so emojis print on Windows consoles
    except Exception:
        pass
    print(f"total distinct lines: {combinations():,}")
    for ctx in _BUCKETS:
        print(f"\n[{ctx}] ({combinations(ctx):,} possible)")
        for _ in range(3):
            print("  ", quip(ctx))
