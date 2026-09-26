# PS4 NOR Inspector v2 — GitHub Ready

A standalone Windows GUI for PS4 NOR dump inspection and diagnostics.

## One-click Windows build

1. Create a new GitHub repository.
2. Upload this entire project folder.
3. Open **Actions**.
4. Select **Build PS4 NOR Inspector v2 (Windows)**.
5. Click **Run workflow**.
6. When it finishes, open the workflow run and download either:
   - `PS4_NOR_Inspector_v2-Windows-x64` — the EXE
   - `PS4_NOR_Inspector_v2-Portable-ZIP` — portable ZIP

The workflow also runs automatically when you push a tag beginning with `v`, for example `v2.0.0`.

## Using the application

- Open NOR dump → **Scan**
- **Copy Diagnostic** creates a GPT-ready diagnostic package without embedding the complete NOR binary.
- **Analyze with GPT** is optional and requires `OPENAI_API_KEY` on the Windows machine.
- Export HTML/JSON reports as needed.

## Security

Never commit an OpenAI API key to GitHub. Set it as an environment variable on the machine running the application if direct GPT analysis is enabled.

## Scope

The validator uses heuristic inspection. PASS/REVIEW/FAIL does not authenticate a dump or prove a hardware/firmware fault.
