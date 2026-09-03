# number-theory-ciphers
# Cipher Lab — Classical Cryptography

An interactive, single-page web app implementing seven classical ciphers from number theory and cryptography. Built for exploring how each cipher works — not just running the algorithm, but seeing the math behind it.

**Live demo:** open `index.html` directly in any browser, or enable GitHub Pages on this repo (Settings → Pages → deploy from `main`) for a shareable link.

## Ciphers included

| Cipher | Core idea |
|---|---|
| Shift Cipher | `c = p + k mod 26` — the Caesar cipher |
| Multiplicative Cipher | `c = a·p mod 26`, requires `gcd(a, 26) = 1` |
| Affine Cipher | `c = a·p + b mod 26`, combines shift and multiplication |
| Playfair Cipher | Digraph substitution using a 5×5 key square |
| Hill Cipher | Linear algebra — encrypts letter pairs via a 2×2 matrix mod 26 |
| Vigenère Cipher | Polyalphabetic shift using a repeating keyword |
| Rail Fence Cipher | Transposition cipher using a zigzag pattern across rails |

## Features

- **Encrypt / decrypt** any message for each cipher, with live input validation (e.g. flags a multiplier that isn't coprime with 26, or a Hill matrix that isn't invertible mod 26)
- **Visual breakdown per cipher** — alphabet mapping tables, the Playfair grid with the row/column/rectangle rule applied to each letter pair, the Hill matrix multiplication worked out step by step, the Vigenère tableau alignment, and the Rail Fence zigzag pattern
- **View code** panel on each module showing the actual encryption/decryption logic, for reference
- Fully client-side — no backend, no build step, no dependencies. Nothing typed into it ever leaves the browser.

## Running it

No installation needed.

- **Locally:** download `index.html` and open it in any browser (desktop or mobile).
- **On GitHub Pages:** push this repo, enable Pages in the repo settings, and visit `https://<your-username>.github.io/<repo-name>/`.

## Project structure

```
cipher-lab/
├── index.html   — the full application (markup, styles, and logic)
└── README.md    — this file
```

## Background

These ciphers are the standard set covered in an introductory number theory / cryptography course: modular arithmetic (Shift, Multiplicative, Affine), matrix-based encryption (Hill), classical polygraphic and polyalphabetic substitution (Playfair, Vigenère), and transposition (Rail Fence). Each implementation follows the textbook algorithm directly, prioritizing clarity over performance.
