#!/usr/bin/env python
# -*- coding: utf-8 -*-

import cmd
import os
import re
import readline
import signal
import sys
import subprocess
import threading
import time
import traceback


__version__ = '0.3.0'


class IMath(cmd.Cmd):
    ignore_case = True
    proc = None
    pty = None
    prompt = 'In[*]:= '
    line = b''
    buf = ''
    interrupt = False
    _init = threading.Lock()
    _running = threading.Lock()
    _shadow = threading.Lock()
    _input = 0
    _res = None
    _cache = dict()

    def __init__(self, kernel='math'):
        cmd.Cmd.__init__(self)
        try:
            self.pty, tty = os.openpty()
            self.proc = subprocess.Popen(kernel, stdin=tty, stdout=tty)
            os.close(tty)
        except AttributeError:
            self.proc = subprocess.Popen(kernel, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        self._init.acquire()
        self._running.acquire()
        t = threading.Thread(target=self.output)
        t.start()
        while self._init.locked():
            if self.proc.poll() != None:
                raise Exception('Quit')
            time.sleep(0.01)

    def console(self):
        readline.set_completer_delims(' \t\n~!@#%^&*()_+-={}[]|\\:;"\'<>,.?/')
        readline.parse_and_bind("tab: complete")
        if self.pty:
            signal.signal(signal.SIGINT, self.signal_handler)
        self.cmdloop(intro=None)

    def complete(self, text, state):
        if self.interrupt:
            return None
        if not text:
            return None
        elif state == 0:
            if self._running.locked():
                return None
            line = readline.get_line_buffer()
            bi = readline.get_begidx()
            self._res = []
            while True:
                if re.search(r'<<\s*"?$', line[:bi], re.IGNORECASE):
                    self.complete_get_contexts(text)
                    break
                else:
                    self.shadow('WriteString[$Output,#,"\n"]&/@Join@@{Names[#,IgnoreCase->'+(
                        'True' if self.ignore_case else 'False'
                        )+'],Contexts[#]}&@"'+text+'*"', True)
                break
        try:
            return self._res[state]
        except IndexError as e:
            return None

    def complete_get_contexts(self, text):
        cache_key = 'contexts'
        res = self._cache.get(cache_key)
        if not res:
            code = '''StringReplace[#, $PathnameSeparator -> "`"] & /@
              Block[{$$l = {}, $$v = $Messages},
               $Messages = {};
               If[Check[SetDirectory[#] =!= $Failed, False],
                  AppendTo[$$l,
                   Check[FileNames[{"*.mx", "*.wl", "*.m",
                      "*.mx/" <> $SystemID <> "/*.mx", "*/Kernel/init.wl",
                      "*/Kernel/init.m", "*/init.m"}, "", 2], {}]];
                  ResetDirectory[]] & /@ $Path;
               $Messages = $$v;
               Join @@ $$l] // Union'''
            self._res = []
            self.shadow('WriteString[$Output,#,"\n"]&/@('+code+")", True)
            res = list(set(re.sub(r'((`Kernel)?`init)?(.(mx|wl|m))$', '`', contexts) for contexts in self._res))
            self._cache[cache_key] = res
        res = list(filter(lambda txt: txt.startswith(text), res))
        res.sort()
        self._res = res
        return

    def shadow(self, cmd, multi=False):
        cmd = '{$$v,$$l}={%,$Line};'+cmd+';$Line=$$l-1;$$v;'
        self._shadow.acquire()
        self._res = [] if multi else None
        self.eval(cmd)

    def eval(self, cmd):
        if cmd == 'EOF' or self.proc.poll() != None:
            return True
        self._running.acquire()
        self.send(cmd)
        while self._running.locked():
            if self.proc.poll() != None:
                return True
            time.sleep(0.01)

    def send(self, cmd):
        if self.proc.poll() != None:
            return True
        cmd += '\n'
        cmd = cmd.encode('utf-8')
        if self.pty:
            self._input = cmd.count(b'\n')
            os.write(self.pty, cmd)
        else:
            self.proc.stdin.write(cmd)
            self.proc.stdin.flush()

    def onecmd(self, line):
        if self.interrupt:
            return self.send(line)
        if line == False:
            self.prompt = ' '*len(self.prompt)
            return
        return self.eval(line)

    def precmd(self, line):
        if line == 'EOF' and self.proc.poll() != None:
            return line
        if self.interrupt:
            return line
        self.buf += ('\n' if self.buf else '')+line
        if not self.finish(self.buf):
            return False
        line = self.buf
        self.buf = ''
        return line

    def finish(self, cmd):
        if cmd == '':
            return True
        sl = str(len(cmd))
        s = '"'+cmd.replace('\\', '\\\\').replace('"', '\\"')+'"'
        self.shadow("WriteString[$Output,SyntaxLength@"+s+">="+sl+"&&!SyntaxQ@"+s+',"\n"]')
        try:
            return self._res != "True"
        finally:
            pass
        return False

    def output(self):
        while True:
            try:
                if self.pty:
                    c = os.read(self.pty, 1)
                else:
                    c = self.proc.stdout.read(1)
            except:
                return
            if c == b'':
                break
            self.handle(c)
        return
        #for line in iter(self.proc.stdout, b''):
        #    self.handle(line.decode('utf-8'))

    def handle(self, c):
        self.line += c
        try:
            line = self.line.decode('utf-8')
        except UnicodeDecodeError:
            return
        flag = re.sub(r'^(\x1b\[..)+', '', line)[:2]

        while True:
            if c != b'\n':
                if flag == 'In':
                    r = re.search(r'^.*(In\[\d+\]:= )', line)
                    if r:
                        self.prompt = r.group(1)
                        if self._init.locked():
                            self._init.release()
                        if self._running.locked():
                            self._running.release()
                        elif self.interrupt:
                            self.interrupt = False
                            self.echo(line)
                        break
                return

            if self._input > 0:
                self._input = self._input - 1
                break

            if self._shadow.locked():
                if line.startswith('\x1b['):
                    break
                w = line.strip()
                if w == '':
                    self._shadow.release()
                    if self._running.locked():
                        self._running.release()
                else:
                    if isinstance(self._res, list):
                        self._res.append(w)
                    else:
                        self._res = w
                break

            self.echo(line)
            break

        self.line = b''

    def echo(self, data):
        sys.stdout.write(data)
        sys.stdout.flush()

    def signal_handler(self, sig, frame):
        if sig == signal.SIGINT:
            if self._running.locked():
                self._running.release()
                self.interrupt = True
                self.prompt = ''
        return


def main():
    import argparse
    parser = argparse.ArgumentParser("imath")
    parser.add_argument("-c", "--case-sensitive", action='store_true', default=False, help="case-sensitive completion")
    parser.add_argument("-k", "--kernel", type=str, default="math", help="kernel path")
    parser.add_argument("-w", "--width", type=int, default=None, help="set page width")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="log level")
    parser.add_argument("-V", "--version", action='version', version=__version__)
    args, options = parser.parse_known_args()

    if '--' in options:
        options.remove('--')

    try:
        cli = IMath([args.kernel]+options)
        cli.ignore_case = not args.case_sensitive
        if args.width != None:
            cli.shadow('SetOptions["stdout", PageWidth->%s]' % (
                args.width if args.width > 0 else "Infinity"))
        cli.console()
    except Exception as e:
        if args.verbose:
            traceback.print_exc()
        else:
            print(e)
    finally:
        try:
            cli.proc.kill()
            os._exit(cli.proc.returncode or 0)
        finally:
            return


if __name__ == "__main__":
    main()
