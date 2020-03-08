#!/usr/bin/env python
# -*- coding: utf-8 -*-

import cmd
import os
import re
import readline
# import signal
import sys
import subprocess
import threading
import time


class IMath(cmd.Cmd):
    proc = None
    prompt = 'In[*]:= '
    line = ''
    buf = ''
    _init = threading.Lock()
    _running = threading.Lock()
    _shadow = threading.Lock()
    _res = None

    def __init__(self, kernel='math'):
        cmd.Cmd.__init__(self)
        self.proc = subprocess.Popen(kernel, stdin=subprocess.PIPE, stdout=subprocess.PIPE, preexec_fn=preexec_function)
        self._init.acquire()
        self._running.acquire()
        t = threading.Thread(target=self.output)
        t.start()
        self._init.acquire()
        self._init.release()

    def console(self):
        readline.set_completer_delims(' \t\n~!@#%^&*()_+-={}[]|\\:;"\'<>,.?/')
        readline.parse_and_bind("tab: complete")
        self.cmdloop(intro=None)

    def complete(self, text, state):
        #origline = readline.get_line_buffer()
        #r = re.search(r'([\$a-z][\$_a-z0-9`]*)$', origline, re.IGNORECASE)
            #w = r.group(1)
        if not text:
            return None
        elif state == 0:
            self._res = []
            self.shadow('Print/@Names["'+text+'*"]', True)
        try:
            return self._res[state]
        except IndexError as e:
            return None

    def shadow(self, cmd, multi=False):
        cmd = '{$$v,$$l}={%,$Line};'+cmd+';$Line=$$l-1;$$v;'
        self._shadow.acquire()
        self._res = [] if multi else None
        self.eval(cmd)

    def eval(self, cmd):
        if self.proc.poll() != None:
            return True
        self._running.acquire()
        self.proc.stdin.write(cmd+"\n")
        self.proc.stdin.flush()
        while self._running.locked():
            if self.proc.poll() != None:
                return True
            time.sleep(0.01)

    def onecmd(self, line):
        if line == False:
            self.prompt = ' '*len(self.prompt)
            return
        return self.eval(line)

    def precmd(self, line):
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
        self.shadow("Print[SyntaxLength["+s+"]<"+sl+"||SyntaxQ["+s+"]]")
        try:
            return self._res != "False"
        finally:
            pass
        return True

    def output(self):
        while True:
            c = self.proc.stdout.read(1)
            if c == b'':
                break
            self.handle(c)
        return
        #for line in iter(self.proc.stdout, b''):
        #    self.handle(line.decode('utf-8'))

    def handle(self, c):
        self.line = self.line + str(c)
        line = self.line
        flag = line[:2]
        if c != '\n':
            if flag == 'In':
                r = re.search(r'^(In\[\d+\]:= )', line)
                if r:
                    self.prompt = r.group(1)
                    if self._init.locked():
                        self._init.release()
                    if self._running.locked():
                        self._running.release()
                    self.line = ''
            return

        if self._shadow.locked():
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
            self.line = ''
            return

        self.echo(line)
        self.line = ''

    def echo(self, data):
        sys.stdout.write(data)
        sys.stdout.flush()

def signal_handler(sig, frame):
    print('You pressed Ctrl+C!')

def preexec_function():
    os.setpgrp()



def main():
    import argparse
    parser = argparse.ArgumentParser("imath")
    parser.add_argument("-k", "--kernel", type=str, default="math", help="kernel path")
    parser.add_argument("-w", "--width", type=int, default=None, help="set page width")
    args = parser.parse_args()

    #signal.signal(signal.SIGINT, signal_handler)
    try:
        cli = IMath(args.kernel)
        if args.width:
            cli.shadow('SetOptions["stdout", PageWidth -> '+str(args.width)+']');
        cli.console()
    except Exception as e:
        print(e)
    finally:
        os._exit(0)


if __name__ == "__main__":
    main()
