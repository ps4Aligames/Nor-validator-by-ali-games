import argparse, binascii, hashlib, html, json, math, os, re, threading, webbrowser
from dataclasses import dataclass, asdict
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog

APP = 'PS4 NOR Inspector'
VERSION = '2.0.0'
BLOCK = 0x10000
KNOWN_SIZES = {0x1000000: '16 MiB', 0x2000000: '32 MiB', 0x4000000: '64 MiB', 0x8000000: '128 MiB'}

@dataclass
class Check:
    name: str
    status: str
    detail: str


def sha256_file(path):
    h = hashlib.sha256(); h1 = hashlib.sha1(); hm = hashlib.md5(); crc = 0; size = 0
    with open(path, 'rb') as f:
        while True:
            b = f.read(4 * 1024 * 1024)
            if not b: break
            size += len(b); h.update(b); h1.update(b); hm.update(b); crc = binascii.crc32(b, crc)
    return {'size': size, 'md5': hm.hexdigest(), 'sha1': h1.hexdigest(), 'sha256': h.hexdigest(), 'crc32': f'{crc & 0xffffffff:08X}'}


def entropy(data):
    if not data: return 0.0
    counts = [0] * 256
    for x in data: counts[x] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def printable_strings(data, min_len=6):
    out = []; start = None
    for i, b in enumerate(data):
        if 32 <= b <= 126:
            if start is None: start = i
        else:
            if start is not None and i - start >= min_len:
                out.append((start, data[start:i].decode('ascii', 'replace')))
            start = None
    if start is not None and len(data) - start >= min_len:
        out.append((start, data[start:].decode('ascii', 'replace')))
    return out


def scan_file(path):
    meta = sha256_file(path); checks = []; size = meta['size']
    if size in KNOWN_SIZES:
        checks.append(Check('NOR capacity', 'PASS', f'{KNOWN_SIZES[size]} ({size:,} bytes) is a common NOR image capacity.'))
    else:
        checks.append(Check('NOR capacity', 'REVIEW', f'{size:,} bytes is not in the common capacity profile; verify dump/chip geometry.'))
    with open(path, 'rb') as f: head = f.read(0x100000)
    non_ff = sum(b != 0xFF for b in head); non_00 = sum(b != 0x00 for b in head)
    if non_ff == 0: checks.append(Check('Header region', 'FAIL', 'First 1 MiB is entirely 0xFF. This commonly indicates an empty/unreadable dump.'))
    elif non_00 == 0: checks.append(Check('Header region', 'FAIL', 'First 1 MiB is entirely 0x00. This commonly indicates an invalid/empty dump.'))
    else: checks.append(Check('Header region', 'PASS', f'Non-uniform data detected in first 1 MiB ({non_ff:,} bytes differ from 0xFF).'))
    max_ff = max_00 = cur_ff = cur_00 = 0
    with open(path, 'rb') as f:
        while True:
            b = f.read(1024 * 1024)
            if not b: break
            for x in b:
                if x == 255: cur_ff += 1; cur_00 = 0; max_ff = max(max_ff, cur_ff)
                elif x == 0: cur_00 += 1; cur_ff = 0; max_00 = max(max_00, cur_00)
                else: cur_ff = cur_00 = 0
    if max_ff >= 8 * 1024 * 1024:
        checks.append(Check('Blank 0xFF runs', 'REVIEW', f'Longest contiguous 0xFF run: {max_ff:,} bytes. Large erased regions may be normal or may indicate a partial dump.'))
    else: checks.append(Check('Blank 0xFF runs', 'PASS', f'Longest contiguous 0xFF run: {max_ff:,} bytes.'))
    blocks = []
    with open(path, 'rb') as f:
        off = 0
        while True:
            b = f.read(BLOCK)
            if not b: break
            blocks.append({'offset': off, 'size': len(b), 'entropy': round(entropy(b), 4)})
            off += len(b)
    high = [x for x in blocks if x['entropy'] >= 7.9]
    checks.append(Check('Entropy profile', 'REVIEW' if len(high) > max(4, len(blocks) * 0.75) else 'PASS', f'{len(high)}/{len(blocks)} blocks have entropy >= 7.9 bits/byte. High entropy is not automatically corruption.'))
    markers = [b'SCEI', b'PlayStation', b'CELL', b'Sony', b'ORBI', b'EMC']; found = []
    with open(path, 'rb') as f: data = f.read()
    for m in markers:
        pos = data.find(m)
        if pos >= 0: found.append(f'{m.decode(errors="ignore")} @ 0x{pos:X}')
    checks.append(Check('Known text markers', 'PASS' if found else 'REVIEW', ', '.join(found[:8]) if found else 'No weak textual markers found; encrypted/compressed regions may legitimately contain none.'))
    return meta, checks, blocks, data


def compare_files(a, b):
    sa = os.path.getsize(a); sb = os.path.getsize(b); size = min(sa, sb); diffs = 0; first = None; ranges = []; run = None
    with open(a, 'rb') as fa, open(b, 'rb') as fb:
        off = 0
        while off < size:
            aa = fa.read(1024 * 1024); bb = fb.read(1024 * 1024)
            for i, (x, y) in enumerate(zip(aa, bb)):
                if x != y:
                    diffs += 1; p = off + i
                    if first is None: first = p
                    if run is None: run = [p, p]
                    elif p == run[1] + 1: run[1] = p
                    else: ranges.append(run); run = [p, p]
            off += len(aa)
    if run: ranges.append(run)
    return {'size_a': sa, 'size_b': sb, 'different_bytes': diffs + abs(sa - sb), 'first_difference': first, 'difference_ranges': ranges[:500]}


def build_gpt_diagnostic(report, recent_logs, mode='diagnostic'):
    safe = dict(report or {})
    safe.pop('file', None)
    payload = {
        'application': APP, 'version': VERSION, 'mode': mode,
        'report': safe,
        'recent_activity': recent_logs[-80:],
        'instructions': 'Analyze the diagnostic data. Identify concrete anomalies, exact offsets when present, likely causes, confidence, and safe next checks. Do not claim a PS4 region/field is corrupt unless the evidence supports it. Do not invent undocumented offsets.'
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def analyze_with_openai(prompt):
    key = os.environ.get('OPENAI_API_KEY', '').strip()
    if not key:
        raise RuntimeError('OPENAI_API_KEY is not configured. Use Copy Diagnostic for manual sharing, or set the environment variable before starting the app.')
    try:
        from openai import OpenAI
    except ImportError:
        raise RuntimeError('The OpenAI Python package is not installed. Run: py -m pip install openai')
    client = OpenAI(api_key=key)
    response = client.responses.create(
        model=os.environ.get('OPENAI_MODEL', 'gpt-5.6-luna'),
        instructions='You are a careful PS4 NOR diagnostic assistant. Analyze only the supplied evidence. Be precise about offsets and distinguish evidence from hypotheses. Give: Summary, Evidence, Likely Cause(s), Exact Location(s), Confidence, and Next Checks. Do not provide firmware bypass, exploit, or unauthorized-access instructions.',
        input=prompt,
    )
    return response.output_text


class App(tk.Tk):
    def __init__(self):
        super().__init__(); self.title(f'{APP} {VERSION}'); self.geometry('1280x820'); self.minsize(1000, 680)
        self.path = None; self.data = b''; self.report = None; self.logs = []
        self._build(); self._theme()
    def _theme(self):
        s = ttk.Style(self); s.configure('Title.TLabel', font=('Segoe UI', 18, 'bold')); s.configure('Status.TLabel', font=('Segoe UI', 10, 'bold'))
    def _build(self):
        top = ttk.Frame(self, padding=14); top.pack(fill='x')
        ttk.Label(top, text='PS4 NOR Inspector', style='Title.TLabel').pack(side='left')
        ttk.Label(top, text='  v2 • diagnostic + GPT assistant', foreground='#666').pack(side='left')
        bar = ttk.Frame(self, padding=(14, 0, 14, 8)); bar.pack(fill='x')
        for text, cmd in [('Open NOR', self.open), ('Scan', self.scan), ('Compare…', self.compare), ('Copy Diagnostic', self.copy_diagnostic), ('Analyze with GPT', self.analyze_gpt), ('Export HTML', self.export_html), ('Export JSON', self.export_json)]:
            ttk.Button(bar, text=text, command=cmd).pack(side='left', padx=3)
        self.filevar = tk.StringVar(value='No file selected'); ttk.Label(bar, textvariable=self.filevar).pack(side='right')
        pan = ttk.Panedwindow(self, orient='horizontal'); pan.pack(fill='both', expand=True, padx=14, pady=8)
        left = ttk.Frame(pan, padding=8); right = ttk.Frame(pan, padding=8); pan.add(left, weight=1); pan.add(right, weight=3)
        ttk.Label(left, text='Validation').pack(anchor='w')
        self.tree = ttk.Treeview(left, columns=('status','detail'), show='headings', height=20); self.tree.heading('status', text='Status'); self.tree.heading('detail', text='Detail'); self.tree.column('status', width=80); self.tree.column('detail', width=360); self.tree.pack(fill='both', expand=True, pady=(5,10))
        ttk.Label(left, text='File information').pack(anchor='w'); self.info = tk.Text(left, height=10, wrap='word', state='disabled'); self.info.pack(fill='both')
        nb = ttk.Notebook(right); nb.pack(fill='both', expand=True)
        self.hex = ttk.Frame(nb); self.strings = ttk.Frame(nb); self.ent = ttk.Frame(nb); self.log = ttk.Frame(nb); self.gpt = ttk.Frame(nb)
        nb.add(self.hex, text='Hex'); nb.add(self.strings, text='Strings'); nb.add(self.ent, text='Entropy'); nb.add(self.log, text='Activity'); nb.add(self.gpt, text='GPT Analysis')
        self.hextext = tk.Text(self.hex, font=('Consolas',10), wrap='none'); self.hextext.pack(fill='both', expand=True)
        self.strtext = tk.Text(self.strings, font=('Consolas',10), wrap='none'); self.strtext.pack(fill='both', expand=True)
        self.enttext = tk.Text(self.ent, font=('Consolas',10), wrap='none'); self.enttext.pack(fill='both', expand=True)
        self.logtext = tk.Text(self.log, font=('Consolas',10), wrap='word'); self.logtext.pack(fill='both', expand=True)
        self.gpttext = tk.Text(self.gpt, font=('Segoe UI',10), wrap='word'); self.gpttext.pack(fill='both', expand=True)
        self.status = tk.StringVar(value='Ready'); ttk.Label(self, textvariable=self.status, style='Status.TLabel', padding=10).pack(fill='x')
    def logmsg(self, s):
        line = f'[{datetime.now():%Y-%m-%d %H:%M:%S}] {s}'; self.logs.append(line); self.logtext.insert('end', line + '\n'); self.logtext.see('end')
    def open(self):
        p = filedialog.askopenfilename(title='Open NOR dump', filetypes=[('Binary files','*.bin *.dump *.nor *.img'),('All files','*.*')])
        if p: self.load(p)
    def load(self, p):
        try:
            self.path = p; self.filevar.set(os.path.basename(p)); self.status.set('Loaded. Click Scan.'); self.logmsg(f'Loaded {p}')
            with open(p, 'rb') as f: self.data = f.read(4096)
            self.show_hex(); self.info.config(state='normal'); self.info.delete('1.0','end'); self.info.insert('end', f'Path: {p}\nSize: {os.path.getsize(p):,} bytes\n'); self.info.config(state='disabled')
        except Exception as e: self.logmsg(f'ERROR load: {e}'); messagebox.showerror(APP, str(e))
    def show_hex(self):
        self.hextext.delete('1.0','end'); d = self.data[:4096]
        for off in range(0, len(d), 16):
            row = d[off:off+16]; hx = ' '.join(f'{x:02X}' for x in row); asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in row); self.hextext.insert('end', f'{off:08X}  {hx:<47}  {asc}\n')
    def scan(self):
        if not self.path: return messagebox.showinfo(APP, 'Open a NOR dump first.')
        try:
            self.status.set('Scanning…'); self.update_idletasks(); meta, checks, blocks, data = scan_file(self.path)
            self.report = {'app': APP, 'version': VERSION, 'generated': datetime.now().isoformat(), 'file': self.path, 'hashes': meta, 'checks': [asdict(x) for x in checks], 'entropy': blocks}
            for x in self.tree.get_children(): self.tree.delete(x)
            for c in checks: self.tree.insert('', 'end', values=(c.status, f'{c.name}: {c.detail}'))
            self.info.config(state='normal'); self.info.delete('1.0','end')
            for k,v in meta.items(): self.info.insert('end', f'{k.upper()}: {v}\n')
            self.info.insert('end', f'\nValidation checks: {len(checks)}\n'); self.info.config(state='disabled')
            self.enttext.delete('1.0','end')
            for x in blocks: self.enttext.insert('end', f'0x{x["offset"]:08X}  {x["entropy"]:0.4f}  {x["size"]:6d}\n')
            self.strtext.delete('1.0','end')
            for off,s in printable_strings(data,6)[:5000]: self.strtext.insert('end', f'0x{off:08X}  {s}\n')
            self.data = data[:4096]; self.show_hex(); self.status.set('Scan complete'); self.logmsg('Scan complete')
        except Exception as e:
            self.logmsg(f'ERROR scan: {e}'); self.status.set('Scan failed'); messagebox.showerror(APP, str(e))
    def compare(self):
        if not self.path: return messagebox.showinfo(APP, 'Open the first NOR dump first.')
        p = filedialog.askopenfilename(title='Select second NOR dump', filetypes=[('Binary files','*.bin *.dump *.nor *.img'),('All files','*.*')])
        if not p: return
        try:
            r = compare_files(self.path, p); self.logmsg(f'Compared against {p}: {r["different_bytes"]:,} differing bytes')
            messagebox.showinfo('NOR Compare', f'Size A: {r["size_a"]:,}\nSize B: {r["size_b"]:,}\nDifferent bytes: {r["different_bytes"]:,}\nFirst difference: {("0x%X" % r["first_difference"]) if r["first_difference"] is not None else "None"}')
        except Exception as e: self.logmsg(f'ERROR compare: {e}'); messagebox.showerror(APP, str(e))
    def copy_diagnostic(self):
        if not self.report: return messagebox.showinfo(APP, 'Run Scan first.')
        packet = build_gpt_diagnostic(self.report, self.logs)
        self.clipboard_clear(); self.clipboard_append(packet); self.update(); self.logmsg('Diagnostic package copied to clipboard (NOR binary not included).')
        messagebox.showinfo('Diagnostic Ready', 'Diagnostic package copied. Paste it into ChatGPT. The full NOR binary was NOT copied.')
    def analyze_gpt(self):
        if not self.report: return messagebox.showinfo(APP, 'Run Scan first.')
        self.gpttext.delete('1.0','end'); self.gpttext.insert('end', 'Analyzing diagnostic data with GPT…\n'); self.status.set('GPT analysis running…'); self.logmsg('Starting GPT analysis (diagnostic metadata only).')
        prompt = build_gpt_diagnostic(self.report, self.logs)
        def worker():
            try: result = analyze_with_openai(prompt); self.after(0, lambda: self._gpt_done(result))
            except Exception as e: self.after(0, lambda: self._gpt_error(str(e)))
        threading.Thread(target=worker, daemon=True).start()
    def _gpt_done(self, result):
        self.gpttext.delete('1.0','end'); self.gpttext.insert('end', result); self.status.set('GPT analysis complete'); self.logmsg('GPT analysis complete.')
    def _gpt_error(self, err):
        self.gpttext.delete('1.0','end'); self.gpttext.insert('end', 'GPT analysis could not be completed.\n\n' + err + '\n\nUse “Copy Diagnostic” to share the safe diagnostic package manually.'); self.status.set('GPT analysis unavailable'); self.logmsg('GPT analysis error: ' + err)
    def export_json(self):
        if not self.report: return messagebox.showinfo(APP, 'Run Scan first.')
        p = filedialog.asksaveasfilename(defaultextension='.json', filetypes=[('JSON','*.json')])
        if p: open(p, 'w', encoding='utf8').write(json.dumps(self.report, indent=2)); self.logmsg(f'JSON report: {p}')
    def export_html(self):
        if not self.report: return messagebox.showinfo(APP, 'Run Scan first.')
        p = filedialog.asksaveasfilename(defaultextension='.html', filetypes=[('HTML','*.html')])
        if not p: return
        rows = ''.join(f'<tr><td>{html.escape(c["status"])}</td><td>{html.escape(c["name"])}</td><td>{html.escape(c["detail"])}</td></tr>' for c in self.report['checks'])
        h = f'''<!doctype html><meta charset="utf-8"><title>PS4 NOR Inspector Report</title><style>body{{font-family:Segoe UI,Arial;margin:40px}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:8px;text-align:left}}code{{word-break:break-all}}</style><h1>PS4 NOR Inspector</h1><p>Generated {html.escape(self.report['generated'])}</p><h2>File</h2><p><code>{html.escape(self.report['file'])}</code></p><pre>{html.escape(json.dumps(self.report['hashes'],indent=2))}</pre><h2>Checks</h2><table><tr><th>Status</th><th>Check</th><th>Detail</th></tr>{rows}</table>'''
        open(p, 'w', encoding='utf8').write(h); self.logmsg(f'HTML report: {p}'); webbrowser.open('file://' + os.path.abspath(p))


def main():
    ap = argparse.ArgumentParser(); ap.add_argument('file', nargs='?'); ap.add_argument('--json', action='store_true'); args = ap.parse_args()
    if args.file and args.json:
        meta, checks, blocks, _ = scan_file(args.file); print(json.dumps({'file':args.file,'hashes':meta,'checks':[asdict(x) for x in checks],'entropy':blocks}, indent=2)); return
    app = App()
    if args.file: app.load(os.path.abspath(args.file)); app.scan()
    app.mainloop()
if __name__ == '__main__': main()
    if args.file:
        if not os.path.isfile(args.file):
            raise SystemExit(f'File not found: {args.file}')
        if args.json:
            meta, checks, blocks, _ = scan_file(args.file)
            print(json.dumps({'app': APP, 'version': VERSION, 'file': args.file, 'hashes': meta, 'checks': [asdict(x) for x in checks], 'entropy': blocks}, indent=2))
        else:
            app = App(); app.load(args.file); app.mainloop()
    else:
        App().mainloop()

if __name__ == '__main__':
    main()
