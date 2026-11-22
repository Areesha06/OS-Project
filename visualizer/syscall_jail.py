#!/usr/bin/env python3
"""PERSON C - "Syscall Jail": a visual replay of the experiment (pygame).

What you see (every decision comes from sandboxlab.replay, i.e. real trace + real policy):
    little people walking right   = the syscalls in a recorded strace trace, in order
    red people with horns         = high-risk syscalls (config/high_risk.txt)
    the bouncer at the door       = the seccomp filter
    the clipboard on the right    = the policy (allow-list); purple "?" = hallucinated name,
                                    red = high-risk, grey = never used in this trace
    the KERNEL club               = the kernel; admitted syscalls go inside
    house turns red, "SIGSYS"     = KILL_PROCESS: the program dies at the first blocked call
Two lanes replay the SAME trace against two different policies (e.g. baseline vs LLM).

Scenes (cycle with R): training run, held-out run, poisoned run, and the jailbreak probe
(an attacker who controls the program tries ptrace/mount/unshare/...).

IMPORTANT for the presentation: this is a REPLAY of recorded traces. Real breakage
numbers come from enforce/run_enforcement.py, which runs programs under seccomp.

Controls (mouse on the bottom buttons, or keys):
    P program   R run/scene   1 / 2 left / right policy   M kill<->errno mode
    U first-occurrence-only on/off   + / - speed   SPACE pause   ENTER restart   ESC quit

Usage:
    python visualizer/syscall_jail.py                 # uses data/ and policies/
    python visualizer/syscall_jail.py --examples      # uses examples/ (works before real data exists)
    python visualizer/syscall_jail.py --program gzip --run heldout --left 0 --right 3
    python visualizer/syscall_jail.py --screenshot shot.png --frames 900   # headless image
"""
import argparse
import math
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sandboxlab import paths, policy, replay, strace_parser, syscalls  # noqa: E402

W, H = 1280, 720
TOP, LANE_H, BAR_Y = 52, 250, 556
GATE_X, HOUSE_R, CLUB_X, BOARD_X = 760, 170, 830, 1010

BG = (38, 52, 40)
GRASS = (66, 102, 58)
ROAD = (150, 150, 145)
ROAD_EDGE = (95, 95, 92)
PANEL = (58, 58, 58)
PANEL_HI = (82, 82, 82)
INK = (240, 239, 236)
MUTED = (175, 174, 168)
GOOD = (60, 190, 110)
BAD = (230, 75, 70)
WARN = (240, 170, 30)
GUEST = (80, 130, 210)
RISK = (215, 60, 55)
HALLU = (160, 110, 230)
KERNEL = (40, 40, 70)

RUN_LABEL = {"training": "Training run (seen)", "heldout": "Held-out run (unseen)",
             "poisoned": "Poisoned run (compromised)", "attack": "Jailbreak probe"}


# ------------------------------------------------------------------ data loading
def discover(data_dir: Path, pol_dir: Path):
    progs = {}
    for d in sorted(p for p in data_dir.iterdir() if p.is_dir() and p.name != "probe"):
        runs = [r for r in ("training", "heldout", "poisoned") if (d / "traces" / f"{r}.strace").exists()]
        pols = sorted(pol_dir.glob(f"baseline/{d.name}/*.json")) + sorted(pol_dir.glob(f"llm/{d.name}/*.json"))
        if runs and pols:
            progs[d.name] = {"runs": runs, "policies": pols}
    probe = data_dir / "probe" / "traces" / "attack.strace"
    return progs, (probe if probe.exists() else None)


def policy_label(doc):
    src = str(doc.get("source"))
    tu = doc.get("trace_used")
    if src == "baseline":
        return f"Baseline (from {tu} trace)"
    lab = f"{src}  prompt {doc.get('prompt')}  r{doc.get('repeat')}"
    return lab + ("  [poisoned]" if tu == "poisoned" else "")


# ------------------------------------------------------------------ actors
class Guest:
    def __init__(self, decision, lane_y):
        self.d = decision
        self.x, self.y = HOUSE_R + 10, lane_y
        self.base_y = lane_y
        self.state = "walk"         # walk -> enter -> gone   |   walk -> reject -> gone
        self.t = 0
        self.alpha = 255
        self.vx, self.vy, self.rot = 0.0, 0.0, 0.0

    def update(self, speed, lane):
        self.t += 1
        if self.state == "walk":
            self.x += 2.4 * speed
            self.y = self.base_y + math.sin(self.t * 0.35) * 1.5
            if self.x >= GATE_X - 22:
                if self.d.allowed:
                    self.state = "enter"
                    lane.on_admit(self.d)
                else:
                    self.state = "reject"
                    self.vx, self.vy = -6.0, -7.0
                    lane.on_block(self.d)
        elif self.state == "enter":
            self.x += 2.4 * speed
            if self.x > CLUB_X + 40:
                self.alpha -= 14 * speed
        elif self.state == "reject":
            self.x += self.vx * speed
            self.y += self.vy * speed
            self.vy += 0.6 * speed
            self.rot += 12 * speed
            if self.y > self.base_y + 40:
                self.alpha -= 10 * speed
        if self.alpha <= 0:
            self.state = "gone"

    def rect(self):
        import pygame
        return pygame.Rect(self.x - 9, self.y - 24, 18, 36)

    def draw(self, surf, font):
        import pygame
        if self.state == "gone":
            return
        c = RISK if self.d.high_risk else GUEST
        if self.state == "reject":
            c = (120, 120, 120)
        a = max(0, min(255, int(self.alpha)))
        g = pygame.Surface((40, 52), pygame.SRCALPHA)
        body = (*c, a)
        pygame.draw.rect(g, body, (14, 22, 12, 16), border_radius=3)        # body
        pygame.draw.circle(g, body, (20, 16), 7)                             # head
        pygame.draw.line(g, body, (16, 38), (14, 47), 3)                     # legs
        pygame.draw.line(g, body, (24, 38), (26, 47), 3)
        if self.d.high_risk:                                                 # horns
            pygame.draw.polygon(g, (*RISK, a), [(14, 11), (12, 3), (17, 9)])
            pygame.draw.polygon(g, (*RISK, a), [(26, 11), (28, 3), (23, 9)])
        if self.rot:
            g = pygame.transform.rotate(g, self.rot)
        surf.blit(g, g.get_rect(center=(self.x, self.y + 6)))
        if self.state != "reject" or self.alpha > 120:
            col = (255, 200, 200) if self.d.high_risk else INK
            txt = font.render(self.d.name if self.state != "reject" else "DENIED", True, col)
            txt.set_alpha(a)
            lift = 14 if self.d.index % 2 == 0 else 28        # stagger labels so neighbours don't overlap
            surf.blit(txt, txt.get_rect(midbottom=(self.x, self.y - lift)))


class Lane:
    def __init__(self, idx, doc, events, mode):
        self.idx = idx
        self.top = TOP + idx * LANE_H
        self.mid = self.top + LANE_H // 2 + 10
        self.doc = doc
        self.label = policy_label(doc)
        cls = syscalls.classify(doc.get("allow", []))
        self.cls = cls
        self.allow = set(cls["valid"])
        self.result = replay.replay(events, self.allow)
        self.mode = mode
        self.guests = []
        self.next_i = 0
        self.dead = False
        self.killed_by = None
        self.admitted = self.blocked = self.risk_in = 0
        self.risk_names = []
        self.flash = 0
        self.alarm_text = ""
        self.push = 0
        self.trace_names = {e.name for e in events}
        self.done = False

    def on_admit(self, d):
        self.admitted += 1
        if d.high_risk:
            self.risk_in += 1
            self.risk_names.append(d.name)
            self.flash = 50
            self.alarm_text = f"HIGH-RISK LET IN: {d.name}"

    def on_block(self, d):
        self.blocked += 1
        self.push = 14
        if self.mode == "kill" and not self.dead:
            self.dead = True
            self.killed_by = d

    def spawn(self):
        if self.dead or self.next_i >= len(self.result.decisions):
            return
        self.guests.append(Guest(self.result.decisions[self.next_i], self.mid))
        self.next_i += 1

    def update(self, speed):
        for g in self.guests:
            g.update(speed, self)
        self.guests = [g for g in self.guests if g.state != "gone"]
        if self.dead:      # a killed process makes no further syscalls
            self.guests = [g for g in self.guests if g.state != "walk"]
        self.flash = max(0, self.flash - 1)
        self.push = max(0, self.push - 1)
        self.done = (self.dead or self.next_i >= len(self.result.decisions)) and not self.guests

    # ---- drawing
    def verdict(self, run):
        hostile = run in ("attack", "poisoned")
        if self.risk_in:
            tail = f", then killed on {self.killed_by.name}" if self.dead else ""
            return BAD, f"ESCAPE: let in {', '.join(self.risk_names)}{tail}"
        if self.dead:
            if self.killed_by.high_risk:
                return GOOD, f"CONTAINED: blocked {self.killed_by.name} -> SIGSYS"
            if hostile:
                return WARN, f"Killed early on {self.killed_by.name} (legit call) -> SIGSYS"
            return BAD, f"BROKEN: legit syscall {self.killed_by.name} blocked -> SIGSYS"
        if not self.done:
            return INK, "RUNNING"
        if self.blocked:
            return WARN, f"Finished, {self.blocked} call(s) denied (errno mode)"
        return GOOD, "SURVIVED: every call was on the list"

    def draw(self, s, f, fs, fb, run):
        import pygame
        r = pygame.Rect(0, self.top, W, LANE_H)
        pygame.draw.rect(s, GRASS, r)
        if self.flash and (self.flash // 6) % 2 == 0:
            ov = pygame.Surface((BOARD_X, LANE_H), pygame.SRCALPHA)
            ov.fill((230, 40, 40, 70))
            s.blit(ov, (0, self.top))
        pygame.draw.line(s, BG, (0, self.top), (W, self.top), 3)
        # road
        pygame.draw.rect(s, ROAD_EDGE, (HOUSE_R - 4, self.mid - 26, CLUB_X - HOUSE_R + 8, 60), border_radius=6)
        pygame.draw.rect(s, ROAD, (HOUSE_R, self.mid - 22, CLUB_X - HOUSE_R, 52), border_radius=4)
        # program house
        vcol, _ = self.verdict(run)
        hc = vcol if (self.dead or self.done) and vcol != INK else (70, 90, 120)
        house = pygame.Rect(20, self.mid - 55, 140, 110)
        pygame.draw.rect(s, hc, house, border_radius=8)
        pygame.draw.polygon(s, (50, 50, 50), [(14, self.mid - 52), (90, self.mid - 95), (166, self.mid - 52)])
        name = self.doc.get("program") if run != "attack" else f"{self.doc.get('program')} (hijacked)"
        s.blit(fb.render(name, True, INK), fb.render(name, True, INK).get_rect(center=(90, self.mid - 18)))
        sub = "SIGSYS" if self.dead else ("process" if not self.done else "exited")
        s.blit(f.render(sub, True, INK), f.render(sub, True, INK).get_rect(center=(90, self.mid + 12)))
        # kernel club
        club = pygame.Rect(CLUB_X, self.top + 30, 160, LANE_H - 60)
        pygame.draw.rect(s, KERNEL, club, border_radius=8)
        pygame.draw.rect(s, (110, 90, 200), club, 3, border_radius=8)
        s.blit(fb.render("KERNEL", True, INK), (CLUB_X + 40, self.top + 42))
        s.blit(fs.render(f"admitted: {self.admitted}", True, MUTED), (CLUB_X + 34, self.top + LANE_H - 58))
        # door + bouncer
        pygame.draw.rect(s, (30, 30, 30), (GATE_X + 10, self.mid - 40, 14, 80))
        bx, by = GATE_X - 2, self.mid - 2
        pygame.draw.rect(s, (25, 25, 30), (bx - 15, by - 6, 30, 36), border_radius=6)            # body
        pygame.draw.circle(s, (200, 160, 120), (bx, by - 16), 12)                                 # head
        pygame.draw.rect(s, (10, 10, 10), (bx - 10, by - 21, 20, 6), border_radius=2)             # sunglasses
        arm = 30 if self.push else 12
        pygame.draw.line(s, (25, 25, 30), (bx - 12, by + 2), (bx - 12 - arm, by - 2), 6)
        pygame.draw.rect(s, (240, 235, 210), (bx + 12, by + 2, 12, 16))                           # clipboard
        tag = fs.render("seccomp", True, INK)
        s.blit(tag, tag.get_rect(center=(bx, by + 40)))
        # header: policy name + verdict
        s.blit(fb.render(("LEFT  " if self.idx == 0 else "RIGHT ") + "bouncer:  " + self.label, True, INK), (16, self.top + 8))
        col, text = self.verdict(run)
        vt = fb.render(text, True, col)
        s.blit(vt, (16, self.top + LANE_H - 30))
        stats = (f"admitted {self.admitted}   turned away {self.blocked}   "
                 f"high-risk let in {self.risk_in}   fake names on list {len(self.cls['hallucinated'])}")
        s.blit(fs.render(stats, True, MUTED), (200, self.top + 34))
        if self.flash:
            at = fb.render(self.alarm_text, True, (255, 220, 220))
            s.blit(at, at.get_rect(center=(GATE_X - 260, self.top + 40)))
        for g in self.guests:
            g.draw(s, fs)
        self.draw_board(s, fs, fb)

    def draw_board(self, s, fs, fb):
        import pygame
        r = pygame.Rect(BOARD_X, self.top + 6, W - BOARD_X - 8, LANE_H - 12)
        pygame.draw.rect(s, (236, 228, 200), r, border_radius=6)
        pygame.draw.rect(s, (120, 100, 60), (r.centerx - 30, r.top - 2, 60, 10), border_radius=3)
        title = f"GUEST LIST  {len(self.cls['valid'])} names"
        s.blit(fb.render(title, True, (40, 40, 40)), (r.left + 10, r.top + 10))
        names = ([(n, "risk") for n in self.cls["high_risk"]] +
                 [(n, "fake") for n in self.cls["hallucinated"]] +
                 [(n, "used") for n in self.cls["valid"] if n in self.trace_names and not syscalls.is_high_risk(n)] +
                 [(n, "unused") for n in self.cls["valid"] if n not in self.trace_names and not syscalls.is_high_risk(n)])
        colw, rowh, rows = (r.width - 16) // 2, 15, (r.height - 40) // 15
        for i, (n, kind) in enumerate(names[: rows * 2]):
            x = r.left + 10 + (i // rows) * colw
            y = r.top + 34 + (i % rows) * rowh
            col = {"risk": RISK, "fake": HALLU, "used": (30, 30, 30), "unused": (140, 135, 120)}[kind]
            label = ("! " if kind == "risk" else "? " if kind == "fake" else "") + n
            s.blit(fs.render(label[:20], True, col), (x, y))
        if len(names) > rows * 2:
            s.blit(fs.render(f"+{len(names) - rows * 2} more", True, (90, 90, 90)), (r.right - 70, r.bottom - 16))


# ------------------------------------------------------------------ app
class App:
    def __init__(self, args):
        import pygame
        self.pg = pygame
        data = paths.EXAMPLES / "data" if args.examples else Path(args.data)
        pols = paths.EXAMPLES / "policies" if args.examples else Path(args.policies)
        self.progs, self.probe = discover(data, pols)
        if not self.progs:
            sys.exit(f"no traces+policies found in {data} / {pols}. Try --examples.")
        self.data = data
        self.prog_names = list(self.progs)
        self.pi = self.prog_names.index(args.program) if args.program in self.progs else 0
        self.run = args.run
        self.left_i, self.right_i = args.left, args.right
        self.mode = args.mode
        self.unique = True
        self.speed_steps = [0.5, 1, 2, 4]
        self.si = 1
        self.paused = False
        self.f = pygame.font.Font(None, 22)
        self.fs = pygame.font.Font(None, 18)
        self.fb = pygame.font.Font(None, 24)
        self.ft = pygame.font.Font(None, 40)
        self.buttons = []
        self.reset()

    # ---- state
    @property
    def prog(self):
        return self.prog_names[self.pi]

    def runs(self):
        r = list(self.progs[self.prog]["runs"])
        return r + (["attack"] if self.probe else [])

    def reset(self):
        if self.run not in self.runs():
            self.run = self.runs()[0]
        trace = self.probe if self.run == "attack" else self.data / self.prog / "traces" / f"{self.run}.strace"
        events = strace_parser.parse_file(trace)
        if self.unique:
            seen, ev = set(), []
            for e in events:
                if e.name not in seen:
                    seen.add(e.name)
                    ev.append(e)
            events = ev
        self.events = events
        pols = self.progs[self.prog]["policies"]
        self.left_i %= len(pols)
        self.right_i %= len(pols)
        if self.right_i == self.left_i and len(pols) > 1 and self.right_i == 0:
            self.right_i = min(2, len(pols) - 1)
        self.lanes = [Lane(0, policy.load_policy(pols[self.left_i]), events, self.mode),
                      Lane(1, policy.load_policy(pols[self.right_i]), events, self.mode)]
        self.tick = 0
        self.spawned = 0

    def cycle(self, what, step=1):
        if what == "prog":
            self.pi = (self.pi + step) % len(self.prog_names)
        elif what == "run":
            rs = self.runs()
            self.run = rs[(rs.index(self.run) + step) % len(rs)]
        elif what == "left":
            self.left_i += step
        elif what == "right":
            self.right_i += step
        elif what == "mode":
            self.mode = "errno" if self.mode == "kill" else "kill"
        elif what == "unique":
            self.unique = not self.unique
        elif what == "speed":
            self.si = (self.si + step) % len(self.speed_steps)
        self.reset()

    # ---- loop pieces
    def update(self):
        if self.paused:
            return
        sp = self.speed_steps[self.si]
        self.tick += sp
        interval = 38
        while self.tick >= interval:
            self.tick -= interval
            for ln in self.lanes:
                ln.spawn()
        for ln in self.lanes:
            ln.update(sp)

    def draw(self, s):
        pg = self.pg
        s.fill(BG)
        # top bar
        pg.draw.rect(s, PANEL, (0, 0, W, TOP))
        s.blit(self.ft.render("SYSCALL JAIL", True, INK), (16, 12))
        scene = f"{self.prog}  |  {RUN_LABEL.get(self.run, self.run)}  |  {self.mode.upper()} mode"
        if self.run == "attack":
            scene = f"Jailbreak: attacker controls {self.prog} and tries to escape  |  {self.mode.upper()} mode"
        st = self.fb.render(scene, True, INK)
        s.blit(st, st.get_rect(center=(W // 2 + 60, TOP // 2)))
        prog_txt = f"calls {max(l.next_i for l in self.lanes)}/{len(self.events)}" + ("  (first occurrences)" if self.unique else "")
        pt = self.fs.render(prog_txt, True, MUTED)
        s.blit(pt, pt.get_rect(topright=(W - 12, 18)))
        for ln in self.lanes:
            ln.draw(s, self.f, self.fs, self.fb, self.run)
        self.draw_bar(s)
        self.draw_tooltip(s)

    def draw_bar(self, s):
        pg = self.pg
        pg.draw.rect(s, PANEL, (0, BAR_Y, W, H - BAR_Y))
        pg.draw.line(s, (30, 30, 30), (0, BAR_Y), (W, BAR_Y), 3)
        self.buttons = []
        specs = [
            ("Program (P)", self.prog, "prog"),
            ("Scene (R)", {"training": "Training", "heldout": "Held-out", "poisoned": "Poisoned",
                           "attack": "Jailbreak"}.get(self.run, self.run), "run"),
            ("Left policy (1)", self.short(self.lanes[0].doc), "left"),
            ("Right policy (2)", self.short(self.lanes[1].doc), "right"),
        ]
        x = 12
        for title, value, key in specs:
            w = 250 if key in ("left", "right") else 180
            box = pg.Rect(x, BAR_Y + 14, w, 64)
            pg.draw.rect(s, PANEL_HI, box, border_radius=6)
            s.blit(self.fs.render(title, True, MUTED), (box.x + 30, box.y + 8))
            s.blit(self.fit(str(value), w - 60), (box.x + 30, box.y + 32))
            lb, rb = pg.Rect(box.x, box.y, 24, 64), pg.Rect(box.right - 24, box.y, 24, 64)
            for b, ch in ((lb, "<"), (rb, ">")):
                pg.draw.rect(s, (100, 100, 100), b, border_radius=6)
                s.blit(self.fb.render(ch, True, INK), self.fb.render(ch, True, INK).get_rect(center=b.center))
            self.buttons += [(lb, key, -1), (rb, key, 1)]
            x += w + 10
        toggles = [(f"Mode: {self.mode.upper()} (M)", "mode"), (f"First only: {'ON' if self.unique else 'OFF'} (U)", "unique"),
                   (f"Speed {self.speed_steps[self.si]}x (+)", "speed"),
                   ("Resume (SPACE)" if self.paused else "Pause (SPACE)", "pause"), ("Restart (ENTER)", "restart")]
        x, y = 12, BAR_Y + 92
        for text, key in toggles:
            t = self.f.render(text, True, INK)
            b = pg.Rect(x, y, t.get_width() + 24, 40)
            pg.draw.rect(s, PANEL_HI, b, border_radius=6)
            s.blit(t, t.get_rect(center=b.center))
            self.buttons.append((b, key, 1))
            x += b.width + 10
        legend = [(GUEST, "syscall"), (RISK, "high-risk syscall"), (HALLU, "? hallucinated name"), (GOOD, "contained / survived"), (BAD, "broken / escaped")]
        lx = 900
        for i, (c, t) in enumerate(legend):
            yy = BAR_Y + 92 + (i % 3) * 18
            xx = lx + (i // 3) * 190
            pg.draw.circle(s, c, (xx, yy + 7), 6)
            s.blit(self.fs.render(t, True, MUTED), (xx + 12, yy))

    def fit(self, text, width):
        """Render text, trimming it with '...' until it fits the given width."""
        t = self.f.render(text, True, INK)
        while t.get_width() > width and len(text) > 4:
            text = text[:-2]
            t = self.f.render(text + "...", True, INK)
        return t

    @staticmethod
    def short(doc):
        src = str(doc.get("source"))
        tu = " poisoned" if doc.get("trace_used") == "poisoned" else ""
        if src == "baseline":
            return "Baseline" + tu
        return f"{src.replace('TEST-FAKE-', 'FAKE ')} p{doc.get('prompt')} r{doc.get('repeat')}{tu}"

    def draw_tooltip(self, s):
        pg = self.pg
        mx, my = pg.mouse.get_pos()
        for ln in self.lanes:
            for g in ln.guests:
                if g.rect().collidepoint(mx, my):
                    d = g.d
                    lines = [d.name, syscalls.describe(d.name)]
                    if d.high_risk:
                        lines.append("HIGH RISK: " + syscalls.high_risk().get(d.name, ""))
                    lines += [f"Left bouncer:  {'ALLOW' if d.name in self.lanes[0].allow else 'BLOCK'}",
                              f"Right bouncer: {'ALLOW' if d.name in self.lanes[1].allow else 'BLOCK'}",
                              f"pid {d.pid}, call #{d.index + 1} in this replay"]
                    surfs = [self.fb.render(lines[0], True, INK)] + [self.fs.render(t, True, INK) for t in lines[1:]]
                    w = max(x.get_width() for x in surfs) + 20
                    h = sum(x.get_height() + 4 for x in surfs) + 14
                    bx, by = min(mx + 14, W - w - 4), min(my + 14, H - h - 4)
                    box = pg.Surface((w, h), pg.SRCALPHA)
                    box.fill((20, 24, 28, 235))
                    s.blit(box, (bx, by))
                    yy = by + 8
                    for x in surfs:
                        s.blit(x, (bx + 10, yy))
                        yy += x.get_height() + 4
                    return

    def click(self, pos):
        for rect, key, step in self.buttons:
            if rect.collidepoint(pos):
                if key == "pause":
                    self.paused = not self.paused
                elif key == "restart":
                    self.reset()
                else:
                    self.cycle(key, step)
                return

    def key(self, k):
        pg = self.pg
        m = {pg.K_p: ("prog", 1), pg.K_r: ("run", 1), pg.K_1: ("left", 1), pg.K_2: ("right", 1),
             pg.K_m: ("mode", 1), pg.K_u: ("unique", 1), pg.K_PLUS: ("speed", 1), pg.K_EQUALS: ("speed", 1),
             pg.K_KP_PLUS: ("speed", 1), pg.K_MINUS: ("speed", -1), pg.K_KP_MINUS: ("speed", -1)}
        if k in m:
            self.cycle(*m[k])
        elif k == pg.K_SPACE:
            self.paused = not self.paused
        elif k in (pg.K_RETURN, pg.K_KP_ENTER):
            self.reset()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--examples", action="store_true", help="use examples/data and examples/policies")
    ap.add_argument("--data", default=str(paths.DATA))
    ap.add_argument("--policies", default=str(paths.POLICIES))
    ap.add_argument("--program", default="gzip")
    ap.add_argument("--run", default="heldout")
    ap.add_argument("--left", type=int, default=0, help="index of left policy in the program's list")
    ap.add_argument("--right", type=int, default=2)
    ap.add_argument("--mode", choices=["kill", "errno"], default="kill")
    ap.add_argument("--screenshot", help="headless: run --frames frames, save PNG, exit")
    ap.add_argument("--frames", type=int, default=600)
    args = ap.parse_args()

    if args.screenshot:
        os.environ["SDL_VIDEODRIVER"] = "dummy"
    import pygame
    pygame.display.init()           # no audio needed
    pygame.font.init()
    screen = pygame.display.set_mode((W, H))
    pygame.display.set_caption("Syscall Jail - Can Local LLMs Write Syscall Sandboxes?")
    app = App(args)
    clock = pygame.time.Clock()
    frame = 0
    while True:
        for ev in pygame.event.get():
            if ev.type == pygame.QUIT or (ev.type == pygame.KEYDOWN and ev.key == pygame.K_ESCAPE):
                pygame.quit()
                return
            if ev.type == pygame.KEYDOWN:
                app.key(ev.key)
            if ev.type == pygame.MOUSEBUTTONDOWN and ev.button == 1:
                app.click(ev.pos)
        app.update()
        app.draw(screen)
        pygame.display.flip()
        frame += 1
        if args.screenshot and frame >= args.frames:
            pygame.image.save(screen, args.screenshot)
            print(f"saved {args.screenshot}")
            pygame.quit()
            return
        if not args.screenshot:
            clock.tick(60)


if __name__ == "__main__":
    main()
