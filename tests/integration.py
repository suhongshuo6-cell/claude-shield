#!/usr/bin/env python3
"""Real binary + TCP + TLS integration lab, no Claude account/network requests."""
import concurrent.futures, contextlib, hashlib, http.server, json, os, pathlib
import select, socket, socketserver, ssl, subprocess, tempfile, threading, time, sys

ROOT=pathlib.Path(__file__).resolve().parents[1]
BIN=pathlib.Path(os.environ.get('CLAUDE_SHIELD_TEST_BINARY',str(ROOT/'build/ClaudeShield')))
validation={'binaryPath':str(BIN.resolve()),'binarySHA256':hashlib.sha256(BIN.read_bytes()).hexdigest(),
            'sourceSHA256':hashlib.sha256((ROOT/'src/main.swift').read_bytes()).hexdigest()}
results=[]
state={'ip':'203.0.113.10','loc':'US','offset':0,'down':False,'malformed':False,'connect_targets':[]}
stop=threading.Event()

def wait(fn, timeout=16):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        try:
            result=fn()
            if result: return result
        except (OSError,ValueError,KeyError): pass
        time.sleep(.1)
    raise AssertionError('condition timed out')

def ok(name, detail=''):
    results.append({'test':name,'passed':True,'detail':detail})
    print('PASS',name,detail,flush=True)

class HTTP(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        state['requests']=state.get('requests',0)+1
        if state.get('stall'):
            time.sleep(10); self.connection.close(); return
        if state['down']:
            self.connection.close(); return
        fallback='fallback=1' in self.path
        if state.get('primary_down') and not fallback:
            self.connection.close();return
        if state.get('success_budget') == 0:
            self.connection.close();return
        if 'success_budget' in state:
            state['success_budget']-=1
        body=('bad-response' if state['malformed'] else json.dumps({'ip':state.get('fallback_ip',state['ip'])}) if fallback else
              f"ip={state['ip']}\nloc={state['loc']}\nts={time.time()+state['offset']}\n").encode()
        self.send_response(200); self.send_header('Content-Length',str(len(body))); self.end_headers()
        with contextlib.suppress(OSError): self.wfile.write(body)
    def log_message(self,*a): pass

class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(20)
        with contextlib.suppress(OSError):
            while not stop.is_set():
                b=self.request.recv(65536)
                if not b: break
                self.request.sendall(b)

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True

class Proxy(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(8)
        with contextlib.suppress(OSError,IndexError):
            b=b''
            while b'\r\n\r\n' not in b:
                x=self.request.recv(8192)
                if not x: return
                b+=x
                if len(b)>16384: return
            header,tail=b.split(b'\r\n\r\n',1)
            target=header.split(b' ')[1]
            state['connect_targets'].append(target)
            if state['down']: return
            if state.get('proxy_delay'): time.sleep(state['proxy_delay'])
            if target==b'echo.test:443' and state.get('business_delay'): time.sleep(state['business_delay'])
            port=echo.server_address[1] if target==b'echo.test:443' else web.server_address[1]
            with socket.create_connection(('127.0.0.1',port),timeout=3) as up:
                self.request.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                if tail: up.sendall(tail)
                while not stop.is_set():
                    ready,_,_=select.select([self.request,up],[],[],.2)
                    for src in ready:
                        d=src.recv(65536)
                        if not d: return
                        (up if src is self.request else self.request).sendall(d)

with tempfile.TemporaryDirectory(prefix='claude-shield-lab-',dir=str(ROOT/'tests')) as td:
    lab=pathlib.Path(td); os.chmod(lab,0o700)
    cnf=lab/'cert.cnf'
    cnf.write_text('[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n[dn]\nCN=probe.test\n[v3]\nsubjectAltName=DNS:probe.test\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\n')
    subprocess.run(['/usr/bin/openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(lab/'key.pem'),'-out',str(lab/'cert.pem'),'-days','1','-config',str(cnf)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
    web=http.server.ThreadingHTTPServer(('127.0.0.1',0),HTTP)
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(lab/'cert.pem',lab/'key.pem')
    web.socket=ctx.wrap_socket(web.socket,server_side=True)
    echo=Server(('127.0.0.1',0),Echo); proxy=Server(('127.0.0.1',0),Proxy)
    for server in (web,echo,proxy): threading.Thread(target=server.serve_forever,daemon=True).start()
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1',0)); port=reserve.getsockname()[1]
    native=lab/'native.json'; meta=lab/'meta.json'; baseline=lab/'rules.js'; cfg=lab/'config.json'; output=lab/'state'
    code=lab/'code-settings.json'
    code_environment={key:f'http://127.0.0.1:{port}' for key in ['HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy']}
    code_environment.update(NO_PROXY='localhost,127.0.0.1,::1',no_proxy='localhost,127.0.0.1,::1')
    code_settings={'env':code_environment,'permissions':{'defaultMode':'default'}}
    def write_code(): code.write_text(json.dumps(code_settings))
    write_code()
    native.write_text(json.dumps({'egressProxyUrl':f'http://127.0.0.1:{port}'})); meta.write_text('{"appliedId":"lab"}'); baseline.write_text('baseline')
    configuration={'port':port,'upstreamPort':proxy.server_address[1], 'expectedIP':'203.0.113.10','expectedCountry':'US',
        'nativeConfig':str(native),'nativeMeta':str(meta),'nativeID':'lab','codeSettings':str(code),
        'baselines':[{'path':str(baseline),'sha256':hashlib.sha256(b'baseline').hexdigest(),'name':'Test rules'}],
        'stateDirectory':str(output),'probeURL':'https://probe.test/cdn-cgi/trace','testCA':str(lab/'cert.pem')}
    cfg.write_text(json.dumps(configuration))
    proc=None
    def launch():
        timing=[] if '--production-timing' in sys.argv else ['--lab-fast']
        return subprocess.Popen([str(BIN),'--headless','--lab',*timing,'--config',str(cfg)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    def status(): return json.loads((output/'status.json').read_text())
    def opened(): return status()['open']
    def connect(expect=200,timeout=4):
        s=socket.create_connection(('127.0.0.1',port),timeout=3); s.settimeout(timeout)
        s.sendall(b'CONNECT echo.test:443 HTTP/1.1\r\nHost: echo.test:443\r\n\r\n')
        b=b''
        while b'\r\n\r\n' not in b:
            x=s.recv(4096)
            if not x: break
            b+=x
        if expect==0: assert not b or b'200' not in b.split(b'\r\n')[0],b
        else: assert str(expect).encode() in b.split(b'\r\n')[0], b
        return s
    def isclosed(s):
        try: return s.recv(1)==b''
        except (ConnectionResetError,BrokenPipeError): return True
        except socket.timeout: return False
    def cycle(name,change,restore):
        s=connect(); start=time.monotonic(); change()
        wait(lambda:not opened(),13)
        assert isclosed(s),'existing tunnel stayed open'; s.close()
        with connect(0): pass
        elapsed=time.monotonic()-start; assert elapsed<13,elapsed
        ok(name,f'closed in {elapsed:.2f}s; new connection refused')
        restore(); wait(opened,18)
    try:
        subprocess.run([str(BIN),'--self-test','--config',str(cfg)],check=True)
        ok('parser/trace/sensitivity/proxy-recovery self-tests')
        # A production invocation must reject a test CA and a nonstandard probe.
        r=subprocess.run([str(BIN),'--headless','--config',str(cfg)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=3)
        assert r.returncode!=0; ok('production rejects lab TLS/probe configuration')
        r=subprocess.run([str(BIN),'--headless','--lab-fast','--config',str(cfg)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=3)
        assert r.returncode!=0;ok('production rejects fast lab timing')
        state['down']=True
        proc=launch(); wait(lambda:(output/'status.json').exists())
        wait(lambda:status().get('transientFailures',0)>0)
        assert not opened(); ok('startup stays closed while exit verification fails')
        state['down']=False;state['success_budget']=1
        wait(opened)
        ok('first verified original-IP result opens gate without second success')
        state.pop('success_budget')
        if '--production-timing' in sys.argv:
            s=connect();state['down']=True;start=time.monotonic()
            wait(lambda:status().get('degraded') is True,22)
            assert opened();s.sendall(b'grace');assert s.recv(5)==b'grace'
            ok('production first transient failure preserves active tunnel')
            wait(lambda:not opened(),48)
            elapsed=time.monotonic()-start
            assert 20<elapsed<48,elapsed
            assert isclosed(s);s.close()
            ok('production persistent failure eventually closes tunnel',f'{elapsed:.2f}s')
            (ROOT/'build/production-timing-results.json').write_text(json.dumps({'passed':True,'tests':results,'accountRequestsSent':0,**validation},indent=2))
            raise SystemExit(0)
        if '--timeout-only' in sys.argv:
            cycle('silent upstream timeout closes active tunnels',lambda:state.update(stall=True),lambda:state.update(stall=False))
            (ROOT/'build/timeout-results.json').write_text(json.dumps({'passed':True,'tests':results,'accountRequestsSent':0,**validation},ensure_ascii=False,indent=2))
            print('SILENT TIMEOUT CHECK PASSED',flush=True)
            raise SystemExit(0)
        state['proxy_delay']=.6
        count=state.get('requests',0)
        wait(lambda:state.get('requests',0)>=count+3,6)
        assert opened() and status()['transientFailures']==0
        state.pop('proxy_delay')
        ok('slow proxy handshake beyond old timeout now verifies successfully')
        assert status()['tunnelHandshakeTimeoutSeconds']==12
        state['business_delay']=6;started=time.monotonic()
        with connect(timeout=9) as s:
            elapsed=time.monotonic()-started
            assert 5.5<=elapsed<9,elapsed
            s.sendall(b'slow-business');assert s.recv(13)==b'slow-business'
        state.pop('business_delay')
        assert opened()
        ok('business CONNECT delayed six seconds succeeds while health probes stay healthy',f'{elapsed:.2f}s')
        state['business_delay']=14;started=time.monotonic()
        with connect(expect=0,timeout=16): pass
        elapsed=time.monotonic()-started
        state.pop('business_delay')
        assert 11.5<=elapsed<14,elapsed
        assert opened(),'one expired business handshake must not close the healthy gate'
        ok('business CONNECT exceeding twelve-second deadline is closed without direct fallback',f'{elapsed:.2f}s')
        s=connect(); payload=os.urandom(1024*1024)
        def send(): s.sendall(payload)
        with concurrent.futures.ThreadPoolExecutor() as pool:
            f=pool.submit(send); received=b''
            while len(received)<len(payload): received+=s.recv(65536)
            f.result()
        assert received==payload; s.close(); ok('1 MiB bidirectional relay intact')
        assert b'echo.test:443' in state['connect_targets']
        ok('CONNECT hostname reaches upstream unchanged; guard needs no local target mapping')
        with socket.create_connection(('127.0.0.1',port),timeout=3) as s:
            s.sendall(b'GET http://example.com/ HTTP/1.1\r\n\r\n'); assert b'405' in s.recv(4096)
        ok('plain HTTP/direct-style requests refused')
        s=connect();state['primary_down']=True
        wait(lambda:'备用 HTTPS' in status()['probeResult'],5)
        for _ in range(4):
            s.sendall(b'alive');assert s.recv(5)==b'alive';assert opened();time.sleep(1)
        state['primary_down']=False;s.close();ok('primary outage with same-IP backup never cuts live tunnel')
        s=connect();state['down']=True
        wait(lambda:status().get('degraded') is True,2)
        assert opened();s.sendall(b'keep');assert s.recv(4)==b'keep'
        state['down']=False;wait(lambda:not status().get('degraded'),3)
        assert opened();s.close();ok('single failed round recovers without cutting active tunnel')
        cycle('changed egress IP closes active tunnels',lambda:state.update(ip='203.0.113.11'),lambda:state.update(ip='203.0.113.10'))
        cycle('changed country closes active tunnels',lambda:state.update(loc='CN'),lambda:state.update(loc='US'))
        cycle('unreachable upstream closes active tunnels',lambda:state.update(down=True),lambda:state.update(down=False))
        s=connect();state['down']=True;wait(lambda:not opened(),7)
        assert isclosed(s);s.close()
        state['down']=False;state['success_budget']=1
        wait(opened,3)
        wait(lambda:status().get('degraded') is True,4)
        assert opened()
        with connect() as s:
            s.sendall(b'recovered');assert s.recv(9)==b'recovered'
        state.pop('success_budget');wait(lambda:not status().get('degraded'),4)
        ok('blocked exit recovers on one success; subsequent transient round does not relock it')
        # Reproduce curl 7 against the actual local proxy listener, not an
        # unreachable remote endpoint. The lab must never launch the real Surge.
        s=connect();proxy_port=proxy.server_address[1]
        proxy.shutdown();proxy.server_close()
        wait(lambda:not opened() and '本机固定代理端口' in status()['reason'],5)
        assert isclosed(s);s.close()
        assert 'curl 7' in status()['probeResult']
        assert status()['automaticProxyRecovery'] is False
        assert not (output/'proxy-recovery.json').exists()
        ok('missing local proxy listener gives curl 7 diagnosis and closes existing tunnel without launching apps in lab')
        proxy=Server(('127.0.0.1',proxy_port),Proxy)
        threading.Thread(target=proxy.serve_forever,daemon=True).start()
        wait(opened,5)
        assert status()['proxyRecoveryStatus']==''
        with connect() as s:
            s.sendall(b'restored');assert s.recv(8)==b'restored'
        ok('restored local listener verifies exit and reopens gate automatically')
        state['offset']=-120;wait(lambda:'备用 HTTPS' in status()['probeResult'],4);assert opened();state['offset']=0
        ok('unreliable primary timestamp can be independently confirmed by backup')
        cycle('malformed probe response closes gate',lambda:state.update(malformed=True),lambda:state.update(malformed=False))
        cycle('rule baseline modification closes gate',lambda:baseline.write_text('modified'),lambda:baseline.write_text('baseline'))
        original=native.read_text()
        cycle('native proxy drift closes gate',lambda:native.write_text('{"egressProxyUrl":"http://127.0.0.1:1"}'),lambda:native.write_text(original))
        cycle('active configuration selection drift closes gate',lambda:meta.write_text('{"appliedId":"other"}'),lambda:meta.write_text('{"appliedId":"lab"}'))
        assert status()['codeSettingsMonitored'] is True
        cycle('missing Code settings closes gate',lambda:code.unlink(),write_code)
        cycle('malformed Code settings closes gate',lambda:code.write_text('{'),write_code)
        cycle('missing Code proxy environment closes gate',lambda:code.write_text('{}'),write_code)
        for key in ['HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy']:
            def change_proxy(key=key):
                modified={**code_environment,key:'http://127.0.0.1:1'}
                code.write_text(json.dumps({'env':modified}))
            cycle(f'Code {key} bypass closes gate',change_proxy,write_code)
        modified=dict(code_environment);modified.pop('https_proxy')
        cycle('missing lowercase Code proxy cannot inherit an unchecked environment',lambda:code.write_text(json.dumps({'env':modified})),write_code)
        for key in ['NO_PROXY','no_proxy']:
            def change_bypass(key=key): code.write_text(json.dumps({'env':{**code_environment,key:'*'}}))
            cycle(f'Code {key} wildcard bypass closes gate',change_bypass,write_code)
        unrelated={**code_settings,'permissions':{'defaultMode':'plan'},'unrelatedPreference':'changed'}
        code.write_text(json.dumps(unrelated));time.sleep(1.2)
        assert opened(),'unrelated Code settings must not be pinned by a whole-file hash'
        with connect() as s:
            s.sendall(b'semantic');assert s.recv(8)==b'semantic'
        write_code();ok('unrelated Code settings changes preserve healthy protected connections')
        original=cfg.read_text()
        cycle('guard configuration tampering closes gate',lambda:cfg.write_text(original+' '),lambda:cfg.write_text(original))
        cycle('manual disconnect persists on disk',lambda:(output/'paused').write_text('manual'),lambda:(output/'paused').unlink())
        s=connect(); proc.kill(); proc.wait(timeout=3); assert isclosed(s); s.close()
        try: socket.create_connection(('127.0.0.1',port),timeout=1)
        except OSError: pass
        else: raise AssertionError('listener remained after crash')
        ok('process crash closes sockets and listener; no fallback exists')
        (output/'paused').write_text('manual'); proc=launch(); wait(lambda:status().get('pid')==proc.pid)
        assert not opened(); ok('manual block survives process restart')
        with connect(0): pass
        (output/'paused').unlink(); wait(opened,18)
        proc.terminate(); proc.wait(timeout=3)
        # Real curl rejects the lab certificate without the explicitly supplied CA.
        configuration['testCA']=None; cfg.write_text(json.dumps(configuration)); proc=launch()
        wait(lambda:'curl 60' in status()['reason'],12); assert not opened(); ok('untrusted TLS certificate is rejected by real curl')
        report={'passed':True,'tests':results,'accountRequestsSent':0,'productionSettingsModified':False,'timing':'10x accelerated isolated lab; production timings covered separately',**validation}
        (ROOT/'build/test-results.json').write_text(json.dumps(report,ensure_ascii=False,indent=2))
        print(f'ALL {len(results)} integration checks passed',flush=True)
    finally:
        if proc and proc.poll() is None: proc.terminate(); proc.wait(timeout=5)
        stop.set()
        for server in (web,echo,proxy): server.shutdown(); server.server_close()
