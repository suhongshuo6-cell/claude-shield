#!/usr/bin/env python3
import datetime, hashlib, http.client, json, os, pathlib, re, socket, subprocess, tempfile, time
ROOT=pathlib.Path(__file__).resolve().parents[1]
results=[]
def ok(name): results.append(name); print('PASS',name,flush=True)
with tempfile.TemporaryDirectory(prefix='console-lab-',dir=ROOT/'tests') as td:
    b=pathlib.Path(td);(b/'state').mkdir();(b/'console').mkdir()
    with socket.socket() as s: s.bind(('127.0.0.1',0)); port=s.getsockname()[1]
    native=b/'native.json';meta=b/'meta.json';rule=b/'rule';rule.write_text('known')
    native.write_text('{"egressProxyUrl":"http://127.0.0.1:17899"}');meta.write_text('{"appliedId":"test"}')
    c={'port':17899,'upstreamPort':1,'expectedIP':'203.0.113.2','expectedCountry':'US','nativeConfig':str(native),'nativeMeta':str(meta),'nativeID':'test','baselines':[{'path':str(rule),'sha256':hashlib.sha256(b'known').hexdigest(),'name':'Test rule'}]}
    (b/'config.json').write_text(json.dumps(c))
    status={'pid':os.getpid(),'open':True,'updatedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds').replace('+00:00','Z'),'reason':'healthy','claudeLegacyConnections':0,'claudeGuardedConnections':1}
    (b/'state/status.json').write_text(json.dumps(status))
    proc=subprocess.Popen([str(ROOT/'build/ClaudeShieldConsole'),'--port',str(port),'--base',str(b),'--html',str(ROOT/'src/index.html')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    def request(method,path,headers=None,body=None):
        conn=http.client.HTTPConnection('127.0.0.1',port,timeout=3)
        conn.request(method,path,body=body,headers=headers or {});r=conn.getresponse(); d=r.read(); result=(r.status,dict(r.getheaders()),d);conn.close();return result
    try:
        for _ in range(50):
            try: r=request('GET','/');break
            except OSError: time.sleep(.1)
        assert r[0]==200
        html=r[2].decode();token=re.search(r"const token='([^']+)'",html)[1]
        assert '__CSRF__' not in html and '__NONCE__' not in html
        assert r[1]['X-Frame-Options']=='DENY' and "default-src 'none'" in r[1]['Content-Security-Policy'] and r[1]['Cache-Control']=='no-store';ok('HTML token injection and restrictive response headers')
        assert request('GET','/',{'Host':'evil.example'})[0]==403;ok('DNS rebinding Host rejected')
        assert request('GET','/api/status',{'Origin':'https://evil.example'})[0]==403;ok('foreign Origin cannot read API')
        assert request('POST','/api/pause')[0]==403;ok('unauthenticated mutation rejected')
        assert request('POST','/api/pause',{'X-Shield-Token':token})[0]==403;ok('missing Origin rejected even with token')
        assert request('POST','/api/pause',{'X-Shield-Token':token,'Origin':'https://evil.example'})[0]==403;ok('foreign Origin rejected even with token')
        assert request('POST','/api/pause',{'X-Shield-Token':'wrong','Origin':f'http://127.0.0.1:{port}'})[0]==403;ok('incorrect anti-forgery token rejected')
        assert request('GET','/api/pause')[0]==404 and not (b/'state/paused').exists();ok('GET cannot change protection state')
        assert request('GET','/../../etc/passwd')[0]==404;ok('arbitrary file paths unavailable')
        headers={'X-Shield-Token':token,'Origin':f'http://127.0.0.1:{port}'}
        assert request('POST','/api/pause',headers)[0]==202 and (b/'state/paused').exists();ok('authorized pause writes only fixture state')
        assert request('POST','/api/resume',headers)[0]==202 and not (b/'state/paused').exists();ok('authorized resume clears fixture pause')
        s=json.loads(request('GET','/api/status')[2]);assert s['serviceFresh'] and s['open'];ok('fresh live service status recognized')
        assert s['consoleVersion']=='1.3.0'
        def config_check(title):
            return next(r for r in json.loads(request('GET','/api/status')[2])['configurationChecks'] if r['title']==title)
        assert config_check('Code 固定代理配置')['status']=='unknown';ok('legacy configuration does not claim Code coverage')
        code=b/'code-settings.json';c['codeSettings']=str(code);(b/'config.json').write_text(json.dumps(c))
        assert config_check('Code 固定代理配置')['status']=='fail';ok('missing Code settings reported')
        proxy_keys=['HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy']
        code_settings={'env':{k:'http://127.0.0.1:17899' for k in proxy_keys}}
        code_settings['env'].update(NO_PROXY='localhost,127.0.0.1,::1',no_proxy='localhost,127.0.0.1,::1')
        code.write_text(json.dumps(code_settings))
        code_row=config_check('Code 固定代理配置')
        assert code_row['status']=='pass' and '配置通过不等于' in code_row['detail'];ok('fixed Code configuration explicitly separates session coverage')
        code_settings['env'].update(NO_PROXY=' ::1 , localhost, 127.0.0.1 ',no_proxy='127.0.0.1,\n::1, localhost\n')
        code.write_text(json.dumps(code_settings))
        assert config_check('Code 固定代理配置')['status']=='pass';ok('loopback bypass order and comma-edge whitespace match core semantics')
        for bypass in ['localhost 127.0.0.1 ::1','localhost,127.0.0.1,::1,','localhost,127.0.0.1,::1,localhost']:
            code_settings['env']['NO_PROXY']=bypass;code.write_text(json.dumps(code_settings))
            assert config_check('Code 固定代理配置')['status']=='fail'
        code_settings['env'].update(NO_PROXY='localhost,127.0.0.1,::1',no_proxy='localhost,127.0.0.1,::1')
        code.write_text(json.dumps(code_settings));ok('space-only bypass, empty entries and duplicate loopback entries rejected')
        for key in proxy_keys+['NO_PROXY','no_proxy']:
            previous=code_settings['env'][key]
            code_settings['env'][key]='*' if key.lower()=='no_proxy' else 'http://user:secret@other.example:8080'
            code.write_text(json.dumps(code_settings))
            code_row=config_check('Code 固定代理配置')
            assert code_row['status']=='fail' and key in code_row['detail'] and 'secret' not in code_row['detail']
            code_settings['env'][key]=previous
        code_settings['permissions']={'defaultMode':'test-value'};code.write_text(json.dumps(code_settings))
        assert config_check('Code 固定代理配置')['status']=='pass';ok('all proxy case variants and bypass lists checked without exposing values or hashing unrelated settings')
        del code_settings['env']['https_proxy'];code.write_text(json.dumps(code_settings))
        assert config_check('Code 固定代理配置')['status']=='fail';ok('missing lowercase proxy cannot masquerade as protected')
        code_settings['env']['https_proxy']='http://127.0.0.1:17899';code.write_text(json.dumps(code_settings))
        assert s['proxyName']=='固定代理'
        c['baselines'][0]['name']='Surge 固定住宅代理链';(b/'config.json').write_text(json.dumps(c))
        assert json.loads(request('GET','/api/status')[2])['proxyName']=='Surge'
        assert config_check('Surge 加密 DNS 配置')['status']=='warn';ok('ordinary DNS configuration remains unverified for privacy')
        encrypted='[General]\nencrypted-dns-server = https://resolver.example/dns-query\nencrypted-dns-follow-outbound-mode = true\n[Rule]\nFINAL,DIRECT\n'
        rule.write_text(encrypted)
        dns_row=config_check('Surge 加密 DNS 配置')
        assert dns_row['status']=='pass' and '这里只核验配置' in dns_row['detail']
        assert config_check('守护的域名处理')['status']=='unknown'
        assert config_check('Surge 固定住宅代理链')['status']=='fail';ok('DNS declarations never override integrity failure or claim runtime privacy')
        rule.write_text(encrypted.replace('= true','= false'))
        assert config_check('Surge 加密 DNS 配置')['status']=='warn'
        rule.write_text(encrypted.replace('https://resolver.example/dns-query','http://resolver.example/dns-query'))
        assert config_check('Surge 加密 DNS 配置')['status']=='warn'
        rule.write_text(encrypted.replace('[Rule]','encrypted-dns-follow-outbound-mode = true\n[Rule]'))
        assert config_check('Surge 加密 DNS 配置')['status']=='warn';ok('direct encrypted DNS, cleartext endpoints and ambiguous duplicate settings not marked configured')
        rule.write_text('known')
        c['baselines'][0]['name']='Clash 固定代理';(b/'config.json').write_text(json.dumps(c))
        assert json.loads(request('GET','/api/status')[2])['proxyName']=='Clash Verge'
        ok('proxy label follows maintained configuration instead of hardcoded Clash')
        status['updatedAt']='2020-01-01T00:00:00Z';(b/'state/status.json').write_text(json.dumps(status))
        s=json.loads(request('GET','/api/status')[2]);assert not s['serviceFresh'] and not s['open'];ok('stale healthy state forced offline')
        assert request('POST','/api/check',headers)[0]==202
        deadline=time.monotonic()+45
        while time.monotonic()<deadline:
            s=json.loads(request('GET','/api/status')[2])
            if s.get('audit',{}).get('completedAt') and not s['checking']:break
            time.sleep(.3)
        assert s['audit']['checks'] and s['audit']['exitMatches'] is False
        assert any(r['status']=='unknown' for r in s['audit']['checks'])
        assert (b/'console/last-audit.json').exists();ok('one-click audit returns failures and explicit unverified risks')
        report={'passed':True,'checks':results,'productionSettingsModified':False,'accountRequestsSent':0}
        (ROOT/'build/console-test-results.json').write_text(json.dumps(report,ensure_ascii=False,indent=2))
        print('ALL',len(results),'console checks passed',flush=True)
    finally:
        proc.terminate();proc.wait(timeout=5)
