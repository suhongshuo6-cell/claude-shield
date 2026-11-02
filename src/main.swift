import Foundation
import AppKit
import Network
import CryptoKit
import Security
import Darwin

// A local CONNECT gate. It never decrypts TLS, reads credentials, or opens a
// direct destination socket. All mutable transport state lives on queue q.
struct Baseline: Codable { let path: String; let sha256: String; let name: String }
struct Configuration: Codable {
    let port: UInt16
    let upstreamPort: UInt16
    let expectedIP: String
    let expectedCountry: String
    let nativeConfig: String
    let nativeMeta: String
    let nativeID: String
    let codeSettings: String?
    let baselines: [Baseline]
    let stateDirectory: String
    let probeURL: String
    let testCA: String?
}
func sha(_ data: Data) -> String { SHA256.hash(data: data).map { String(format:"%02x", $0) }.joined() }
func readJSON(_ path: String) -> [String: Any]? {
    guard let d = try? Data(contentsOf: URL(fileURLWithPath:path)) else { return nil }
    return (try? JSONSerialization.jsonObject(with:d)) as? [String:Any]
}
func codeProxyIssue(_ settings:[String:Any]?, port:UInt16) -> String? {
    guard let settings=settings else { return "Claude Code 代理设置缺失或无法解析" }
    guard let environment=settings["env"] as? [String:Any] else { return "Claude Code 代理环境设置缺失" }
    let expected="http://127.0.0.1:\(port)"
    for key in ["HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","http_proxy","https_proxy","all_proxy"] {
        guard let value=environment[key] as? String else { return "Claude Code \(key) 未固定到保护入口" }
        guard value==expected else { return "Claude Code \(key) 已偏离保护入口" }
    }
    let loopback:Set<String>=["localhost","127.0.0.1","::1"]
    for key in ["NO_PROXY","no_proxy"] {
        guard let value=environment[key] as? String else { return "Claude Code \(key) 本机例外设置缺失" }
        let hosts=value.components(separatedBy:",").map{$0.trimmingCharacters(in:.whitespacesAndNewlines)}
        guard hosts.count==loopback.count,Set(hosts)==loopback else { return "Claude Code \(key) 必须仅包含 localhost、127.0.0.1 和 ::1" }
    }
    return nil
}
func privateWrite(_ data: Data, _ path: String) throws {
    try data.write(to:URL(fileURLWithPath:path), options:.atomic)
    try FileManager.default.setAttributes([.posixPermissions:0o600], ofItemAtPath:path)
}
func authority(_ header: Data) -> String? {
    guard let s = String(data:header, encoding:.utf8), !s.contains("\0") else { return nil }
    let lines = s.components(separatedBy:"\r\n")
    let bits = (lines.first ?? "").split(separator:" ", omittingEmptySubsequences:false)
    guard bits.count == 3, bits[0] == "CONNECT", ["HTTP/1.0","HTTP/1.1"].contains(String(bits[2])) else { return nil }
    let a = String(bits[1])
    // HTTPS only, DNS name or bracketed IPv6; no embedded credentials or URI.
    guard a.range(of:#"^(?:[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?|\[[0-9A-Fa-f:]+\]):443$"#, options:.regularExpression) != nil else { return nil }
    return a
}
func traceCheck(_ body: String, _ c: Configuration, now: Double) -> String? {
    var values = [String:String]()
    for line in body.split(separator:"\n") {
        let pair = line.split(separator:"=", maxSplits:1, omittingEmptySubsequences:false)
        if pair.count == 2 {
            let key = String(pair[0]); if values[key] != nil { return "检测响应存在重复字段" }
            values[key] = String(pair[1])
        }
    }
    guard values["ip"] == c.expectedIP else { return "出口 IP 与已确认基线不同" }
    guard values["loc"] == c.expectedCountry else { return "出口地区与基线不同" }
    guard let ts = Double(values["ts"] ?? ""), abs(ts-now) < 60 else { return "检测响应时间或系统时钟异常" }
    return nil
}
enum ProbeVerdict { case good,transient(String),unsafe(String) }
func validIP(_ s:String)->Bool {
    var v4=in_addr();var v6=in6_addr()
    return s.withCString{inet_pton(AF_INET,$0,&v4)==1 || inet_pton(AF_INET6,$0,&v6)==1}
}
func verdict(_ body:String,_ c:Configuration,fallback:Bool,now:Double)->ProbeVerdict {
    if fallback {
        guard let data=body.data(using:.utf8),let json=(try? JSONSerialization.jsonObject(with:data)) as? [String:Any],let ip=json["ip"] as? String,validIP(ip) else{return .transient("备用出口检测响应无效")}
        return ip==c.expectedIP ? .good:.unsafe("出口 IP 与已确认基线不同（备用检测）")
    }
    var fields=[String:String]()
    for line in body.split(separator:"\n") {
        let pair=line.split(separator:"=",maxSplits:1,omittingEmptySubsequences:false)
        if pair.count==2 {let k=String(pair[0]);if fields[k] != nil{return .transient("检测响应存在重复字段")};fields[k]=String(pair[1])}
    }
    guard let ip=fields["ip"],validIP(ip),let country=fields["loc"],country.count==2,let ts=Double(fields["ts"] ?? ""),abs(ts-now)<60 else{return .transient("检测响应不完整或时间无效")}
    if ip != c.expectedIP{return .unsafe("出口 IP 与已确认基线不同")}
    if country != c.expectedCountry{return .unsafe("出口地区与基线不同")}
    return .good
}
struct Sensitivity {
    let scale:Double
    var interval:Double {10*scale}
    var timeout:Double {12*scale}
    var connectTimeout:Double {8*scale}
    var grace:Double {30*scale}
    var lease:Double {45*scale}
    func shouldBlock(failures:Int,age:Double)->Bool{failures>=3 && age>=grace}
}

// Only a missing local proxy may trigger a launch. Network timeouts, changed
// exits and TLS failures must never cause proxy restarts or route changes.
struct ProxyRecoveryState: Codable {
    var lastAttempt:Double?
    var attemptedThisOutage=false
    func canAttempt(now:Double,curlCode:Int32,enabled:Bool,appRunning:Bool,paused:Bool,configurationOK:Bool)->Bool {
        enabled && curlCode==7 && !appRunning && !paused && configurationOK && !attemptedThisOutage &&
        (lastAttempt == nil || now-(lastAttempt ?? now)>=600)
    }
    mutating func reserve(now:Double) {lastAttempt=now;attemptedThisOutage=true}
    mutating func verified() {attemptedThisOutage=false}
}
let surgeApplicationURL=URL(fileURLWithPath:"/Applications/Surge.app")
let surgeBundleID="com.nssurge.surge-mac"
func trustedSurgeApplication()->Bool {
    var code:SecStaticCode?
    var requirement:SecRequirement?
    let rule="anchor apple generic and identifier \"com.nssurge.surge-mac\" and certificate leaf[subject.OU] = \"YCKFLA6N72\""
    guard SecStaticCodeCreateWithPath(surgeApplicationURL as CFURL,[],&code)==errSecSuccess,
          SecRequirementCreateWithString(rule as CFString,[],&requirement)==errSecSuccess,
          let code=code,let requirement=requirement else{return false}
    return SecStaticCodeCheckValidity(code,SecCSFlags(rawValue:kSecCSStrictValidate),requirement)==errSecSuccess
}

final class Tunnel {
    // Business CONNECT handshakes must tolerate the same slow upstream as the
    // health checks. This deadline is never shortened by accelerated lab timing.
    static let upstreamHandshakeTimeout:TimeInterval=12
    let id = UUID()
    let client: NWConnection
    var upstream: NWConnection?
    var initial = Data()
    var closed = false
    weak var gate: Gate?
    init(_ client:NWConnection, _ gate:Gate) { self.client=client; self.gate=gate }
    func start() {
        guard let gate=gate else { return }
        client.stateUpdateHandler = { [weak self] state in
            if case .failed = state { self?.close() }
            if case .cancelled = state { self?.close() }
        }
        client.start(queue:gate.q)
        readHeader()
        gate.q.asyncAfter(deadline:.now()+5) { [weak self] in
            if self?.upstream == nil { self?.close() }
        }
    }
    func readHeader() {
        client.receive(minimumIncompleteLength:1, maximumLength:8192) { [weak self] data, _, end, error in
            guard let self=self, !self.closed, let gate=self.gate else { return }
            if let data=data { self.initial.append(data) }
            guard self.initial.count <= 16384 else { self.reject(431); return }
            if let range=self.initial.range(of:Data("\r\n\r\n".utf8)) {
                guard let target=authority(self.initial.subdata(in:0..<range.lowerBound)) else { self.reject(405); return }
                let tail=self.initial.subdata(in:range.upperBound..<self.initial.count)
                self.initial.removeAll()
                guard gate.admit() else { self.reject(503); return }
                self.connect(target, tail:tail)
            } else if end || error != nil { self.close() }
            else { self.readHeader() }
        }
    }
    func connect(_ target:String, tail:Data) {
        guard let gate=gate else { close(); return }
        // The only transport destination this binary constructs is loopback.
        let options=NWProtocolTCP.Options(); options.connectionTimeout=3
        let params=NWParameters(tls:nil,tcp:options)
        let up=NWConnection(host:"127.0.0.1", port:NWEndpoint.Port(rawValue:gate.c.upstreamPort)!, using:params)
        upstream=up
        up.stateUpdateHandler = { [weak self] state in
            guard let self=self, !self.closed else { return }
            switch state {
            case .ready:
                guard self.gate?.admit() == true else { self.close(); return }
                let request=Data("CONNECT \(target) HTTP/1.1\r\nHost: \(target)\r\n\r\n".utf8)
                up.send(content:request, completion:.contentProcessed { [weak self] error in
                    guard let self=self else { return }
                    if error != nil { self.close(); return }
                    self.readUpstreamHeader(Data(), tail:tail)
                })
            case .failed, .cancelled: self.close()
            default: break
            }
        }
        up.start(queue:gate.q)
        gate.q.asyncAfter(deadline:.now()+Tunnel.upstreamHandshakeTimeout) { [weak self] in
            if self?.handshakeComplete == false { self?.close() }
        }
    }
    var handshakeComplete=false
    func readUpstreamHeader(_ previous:Data, tail:Data) {
        guard let up=upstream else { close(); return }
        up.receive(minimumIncompleteLength:1,maximumLength:8192) { [weak self] data, _, end, error in
            guard let self=self, !self.closed else { return }
            var accumulated=previous; if let data=data { accumulated.append(data) }
            guard accumulated.count <= 16384 else { self.close(); return }
            if let range=accumulated.range(of:Data("\r\n\r\n".utf8)) {
                let header=String(data:accumulated.subdata(in:0..<range.lowerBound),encoding:.utf8) ?? ""
                let status=header.components(separatedBy:"\r\n")[0].split(separator:" ")
                guard status.count >= 2, status[1] == "200", self.gate?.admit() == true else { self.reject(502); return }
                self.handshakeComplete=true
                let excess=accumulated.subdata(in:range.upperBound..<accumulated.count)
                self.client.send(content:Data("HTTP/1.1 200 Connection Established\r\n\r\n".utf8)+excess,
                                 completion:.contentProcessed { [weak self] error in
                    guard let self=self, !self.closed else { return }
                    if error != nil { self.close(); return }
                    if tail.isEmpty { self.pump(self.client,up) }
                    else { up.send(content:tail,completion:.contentProcessed { [weak self] error in
                        guard let self=self else { return }
                        if error != nil { self.close() } else { self.pump(self.client,up) }
                    }) }
                    self.pump(up,self.client)
                })
            } else if end || error != nil { self.close() }
            else { self.readUpstreamHeader(accumulated,tail:tail) }
        }
    }
    func pump(_ from:NWConnection, _ to:NWConnection) {
        from.receive(minimumIncompleteLength:1,maximumLength:65536) { [weak self] data, _, end, error in
            guard let self=self, !self.closed else { return }
            guard let gate=self.gate, gate.isOpen else { self.close(); return }
            guard ProcessInfo.processInfo.systemUptime-gate.lastGood <= gate.sensitivity.lease else {
                gate.block("出口检测已过期，连接已关闭"); return
            }
            if error != nil { self.close(); return }
            if let data=data, !data.isEmpty {
                to.send(content:data,completion:.contentProcessed { [weak self] error in
                    guard let self=self else { return }
                    if error != nil || end { self.close() } else { self.pump(from,to) }
                })
            } else if end { self.close() } else { self.pump(from,to) }
        }
    }
    func reject(_ status:Int) {
        client.send(content:Data("HTTP/1.1 \(status) Protection Gate Closed\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".utf8),completion:.contentProcessed { [weak self] _ in self?.close() })
    }
    func close() {
        guard !closed else { return }; closed=true
        client.stateUpdateHandler=nil; upstream?.stateUpdateHandler=nil
        client.cancel(); upstream?.cancel(); gate?.tunnels.removeValue(forKey:id)
    }
}

final class Gate {
    let q=DispatchQueue(label:"local.claude.shield.transport")
    let c:Configuration
    let configPath:String
    let configDigest:String
    var listener:NWListener?
    var timer:DispatchSourceTimer?
    var pathMonitor:NWPathMonitor?
    var tunnels=[UUID:Tunnel]()
    var isOpen=false
    var reason="启动检查中，连接暂时关闭"
    var lastGood:Double=0
    var generation=0
    var probeRunning=false
    var lastProbeStarted:Double = -100
    var probeProcess:Process?
    var paused=false
    var sleeping=false
    var ready=false
    var lastTick=ProcessInfo.processInfo.systemUptime
    var probeResult="尚未检测"
    var onChange:(([String:Any])->Void)?
    var hasPath=false
    var lastPath=""
    var snapshotCounter=0
    var legacyConnections = -1
    var guardedConnections = -1
    var coverageRunning=false
    var lastCoverage:Double = -100
    var transientFailures=0
    var degraded=false
    var firstProbeIssue=""
    var proxyRecovery=ProxyRecoveryState()
    var proxyRecoveryStatus=""
    var recoveryChecking=false
    var recoveryStatePath:String {c.stateDirectory+"/proxy-recovery.json"}
    // Environment-specific auto-recovery is disabled in the public release.
    var usesSurge:Bool { false }
    let sensitivity:Sensitivity
    let lab:Bool
    init(_ c:Configuration, path:String, lab:Bool,fastLab:Bool=false) throws {
        self.c=c; self.configPath=path; self.lab=lab
        guard !fastLab || lab else{throw NSError(domain:"Fast test timing requires isolated lab",code:1)}
        sensitivity=Sensitivity(scale:fastLab ? 0.1:1)
        configDigest=sha(try Data(contentsOf:URL(fileURLWithPath:path)))
        guard c.port != c.upstreamPort, c.port >= 1024, c.upstreamPort >= 1024,
              URL(string:c.probeURL)?.scheme == "https", !c.expectedIP.isEmpty,
              lab || (c.testCA == nil && c.probeURL == "https://www.cloudflare.com/cdn-cgi/trace") else {
            throw NSError(domain:"Invalid configuration",code:1)
        }
        try FileManager.default.createDirectory(atPath:c.stateDirectory,withIntermediateDirectories:true,attributes:[.posixPermissions:0o700])
        paused=FileManager.default.fileExists(atPath:c.stateDirectory+"/paused")
        if FileManager.default.fileExists(atPath:recoveryStatePath) {
            if let data=try? Data(contentsOf:URL(fileURLWithPath:recoveryStatePath)),
               let state=try? JSONDecoder().decode(ProxyRecoveryState.self,from:data) {proxyRecovery=state}
            else {proxyRecovery=ProxyRecoveryState(lastAttempt:Date().timeIntervalSince1970,attemptedThisOutage:true)}
        }
    }
    func start() throws {
        q.async {
            self.reason=self.paused ? "已手动断开 Claude 网络" : "启动检查中，连接暂时关闭"
            self.publish()
        }
        let p=NWParameters.tcp
        p.requiredLocalEndpoint = .hostPort(host:"127.0.0.1",port:NWEndpoint.Port(rawValue:c.port)!)
        p.allowLocalEndpointReuse=false
        let l=try NWListener(using:p); listener=l
        l.newConnectionHandler = { [weak self] connection in
            guard let self=self else { connection.cancel(); return }
            guard self.tunnels.count < 256 else { connection.cancel(); return }
            let t=Tunnel(connection,self); self.tunnels[t.id]=t; t.start()
        }
        l.stateUpdateHandler = { [weak self] state in
            guard let self=self else { return }
            if case .ready = state { self.ready=true; self.tick() }
            if case .failed = state { self.ready=false; self.block("本机保护端口无法监听"); exit(2) }
        }
        l.start(queue:q)
        let t=DispatchSource.makeTimerSource(queue:q); timer=t
        t.schedule(deadline:.now(),repeating:sensitivity.scale)
        t.setEventHandler { [weak self] in self?.tick() }; t.resume()
        if !lab {
            let monitor=NWPathMonitor(); pathMonitor=monitor
            monitor.pathUpdateHandler = { [weak self] path in
                guard let self=self else { return }
                // A path notification requests verification; it does not by
                // itself prove the fixed proxy's public exit has changed.
                let signature="\(path.status)|wifi:\(path.usesInterfaceType(.wifi))|wired:\(path.usesInterfaceType(.wiredEthernet))|cell:\(path.usesInterfaceType(.cellular))|\(path.isExpensive)|\(path.supportsIPv4)|\(path.supportsIPv6)"
                if !self.hasPath || signature != self.lastPath {
                    self.hasPath=true; self.lastPath=signature
                    self.lastProbeStarted = -100
                }
            }
            monitor.start(queue:q)
        }
    }
    func configurationIssue() -> String? {
        guard let d=try? Data(contentsOf:URL(fileURLWithPath:configPath)), sha(d)==configDigest else { return "保护配置被修改：需维护检查" }
        guard let meta=readJSON(c.nativeMeta), meta["appliedId"] as? String == c.nativeID,
              let native=readJSON(c.nativeConfig), native["egressProxyUrl"] as? String == "http://127.0.0.1:\(c.port)",
              native["egressProxyPacUrl"] == nil else { return "Claude 固定代理配置已偏离保护入口" }
        if let path=c.codeSettings, let issue=codeProxyIssue(readJSON(path),port:c.port) { return issue }
        for b in c.baselines {
            guard let d=try? Data(contentsOf:URL(fileURLWithPath:b.path)), sha(d)==b.sha256 else { return "\(b.name)发生变化：需维护检查" }
        }
        return nil
    }
    func block(_ message:String) {
        let changed=isOpen || reason != message
        isOpen=false; lastGood=0; generation += 1; reason=message;degraded=false
        if !message.hasPrefix("本机固定代理端口") {proxyRecoveryStatus=""}
        for t in Array(tunnels.values) { t.close() }
        if changed { record("blocked",message); publish() }
    }
    func admit() -> Bool {
        if let issue=configurationIssue() { block(issue); return false }
        if paused || sleeping || !ready { return false }
        if !isOpen { probe(); return false }
        if ProcessInfo.processInfo.systemUptime-lastGood > sensitivity.lease {
            block("出口检测已过期，等待重新验证"); probe(); return false
        }
        return isOpen
    }
    func tick() {
        defer{snapshotCounter+=1;if snapshotCounter % 5 == 0 {publish()}}
        let now=ProcessInfo.processInfo.systemUptime
        if now-lastTick > sensitivity.lease { block("检测程序长时间停顿，重新验证出口") }
        lastTick=now
        if let issue=configurationIssue() { if reason != issue || isOpen { block(issue) }; return }
        let diskPause=FileManager.default.fileExists(atPath:c.stateDirectory+"/paused")
        if diskPause != paused { paused=diskPause; block(paused ? "已手动断开 Claude 网络" : "正在重新验证出口") }
        if paused || sleeping { return }
        if isOpen && now-lastGood > sensitivity.lease { block("连续 45 秒未能验证出口，连接已关闭") }
        if !probeRunning && now-lastProbeStarted >= sensitivity.interval-0.01 { probe() }
        if !lab && !coverageRunning && now-lastCoverage >= 15 { checkCoverage() }
    }
    func probe() {
        guard !probeRunning, !paused, !sleeping, ready, configurationIssue() == nil else { return }
        guard ProcessInfo.processInfo.systemUptime-lastProbeStarted>=sensitivity.interval-0.01 else{return}
        probeRunning=true; lastProbeStarted=ProcessInfo.processInfo.systemUptime;firstProbeIssue=""
        runProbe(fallback:false,epoch:generation)
    }
    func runProbe(fallback:Bool,epoch:Int) {
        let p=Process(); probeProcess=p; p.executableURL=URL(fileURLWithPath:"/usr/bin/curl")
        var args=["-q","--silent","--show-error","--fail","--connect-timeout",String(sensitivity.connectTimeout),"--max-time",String(sensitivity.timeout),"--max-filesize","8192","--proto","=https","--http1.1","--proxy","http://127.0.0.1:\(c.upstreamPort)","--noproxy","","--header","Cache-Control: no-cache"]
        if lab, let ca=c.testCA { args += ["--cacert",ca] }
        let url=fallback ? (lab ? c.probeURL+"?fallback=1":"https://api.ipify.org?format=json"):c.probeURL
        args += [url]; p.arguments=args
        p.environment=["PATH":"/usr/bin:/bin","LANG":"C"]
        let out=Pipe(); p.standardOutput=out; p.standardError=FileHandle.nullDevice
        p.terminationHandler = { [weak self] process in
            let data=out.fileHandleForReading.readDataToEndOfFile()
            self?.q.async { [weak self] in
                guard let self=self else { return }; self.probeProcess=nil
                guard epoch == self.generation, !self.paused, !self.sleeping else {self.probeRunning=false;return}
                guard self.configurationIssue() == nil else { self.probeRunning=false;self.block("配置检查失败"); return }
                if process.terminationStatus != 0 {
                    if process.terminationStatus==7 {
                        self.probeRunning=false;self.transientFailures+=1
                        self.probeResult="无法连接本机固定代理端口 127.0.0.1:\(self.c.upstreamPort)（curl 7），不是检测到 IP 改变"
                        self.block("本机固定代理端口不可用，连接已阻断")
                        self.recoverMissingProxy();self.publish();return
                    }
                    if [51,60,77,90,91].contains(process.terminationStatus) {
                        self.probeRunning=false;self.probeResult="HTTPS 证书校验失败（curl \(process.terminationStatus)）";self.block(self.probeResult);return
                    }
                    self.transientProbe("检测未成功（curl \(process.terminationStatus)）",fallback:fallback,epoch:epoch);return
                }
                let body=String(data:data,encoding:.utf8) ?? ""
                switch verdict(body,self.c,fallback:fallback,now:Date().timeIntervalSince1970) {
                case .unsafe(let issue):self.probeRunning=false;self.probeResult=issue;self.block(issue);return
                case .transient(let issue):self.transientProbe(issue,fallback:fallback,epoch:epoch);return
                case .good:break
                }
                self.probeRunning=false;self.transientFailures=0;self.degraded=false
                if self.proxyRecovery.attemptedThisOutage {
                    self.proxyRecovery.verified()
                    try? privateWrite(JSONEncoder().encode(self.proxyRecovery),self.recoveryStatePath)
                }
                self.proxyRecoveryStatus=""
                self.lastGood=ProcessInfo.processInfo.systemUptime
                self.probeResult=fallback ? "备用 HTTPS 核验：仍为已确认的固定 IP（不另作实时地区判定）":"出口 IP、地区、TLS 与响应时间检查通过"
                // A current verified result already establishes the original exit.
                // Waiting for consecutive rounds can indefinitely lock out a slow
                // but valid proxy. Transient failures after recovery use the grace window.
                if !self.isOpen {
                    self.isOpen=true; self.reason="连接保护中"; self.record("healthy",self.probeResult)
                } else {self.reason="连接保护中"}
                self.publish()
            }
        }
        do { try p.run() } catch { probeRunning=false; probeProcess=nil; block("无法启动出口检测") }
        q.asyncAfter(deadline:.now()+sensitivity.timeout+1) { [weak p] in
            if let p=p,p.isRunning {p.terminate()}
        }
    }
    func transientProbe(_ message:String,fallback:Bool,epoch:Int) {
        if !fallback {firstProbeIssue=message;runProbe(fallback:true,epoch:epoch);return}
        probeRunning=false;transientFailures+=1
        probeResult="主、备用检测均未成功：\(firstProbeIssue)；\(message)"
        let age=ProcessInfo.processInfo.systemUptime-lastGood
        if isOpen && sensitivity.shouldBlock(failures:transientFailures,age:age) {
            block("持续无法验证固定出口（连续 \(transientFailures) 轮，已超过 30 秒）");return
        }
        if isOpen {
            if !degraded {record("observing","检测暂时波动，保留连接并继续核验")}
            degraded=true;reason="网络波动，观察中（连续 \(transientFailures) 轮未通过，暂不切断）"
        }else{reason="出口检测暂未成功，等待原出口验证后恢复"}
        publish()
    }
    func recoverMissingProxy() {
        guard usesSurge,!recoveryChecking,!paused,!sleeping,configurationIssue()==nil else{return}
        recoveryChecking=true
        DispatchQueue.main.async { [weak self] in
            let running=NSRunningApplication.runningApplications(withBundleIdentifier:surgeBundleID).contains{!$0.isTerminated}
            self?.q.async { [weak self] in
                guard let self=self else{return}
                self.recoveryChecking=false
                guard !self.isOpen,!self.paused,!self.sleeping,self.configurationIssue()==nil else{return}
                if running {
                    self.proxyRecoveryStatus="Surge 仍在运行，但固定端口不可用；请检查 Surge 服务。守护不会反复重启它。"
                    self.publish();return
                }
                let now=Date().timeIntervalSince1970
                guard self.proxyRecovery.canAttempt(now:now,curlCode:7,enabled:self.usesSurge,appRunning:running,paused:self.paused,configurationOK:true) else {
                    self.proxyRecoveryStatus="Surge 未运行；本次故障已尝试自动恢复，或仍在 10 分钟冷却期。请手动打开 Surge。"
                    self.publish();return
                }
                // Persist before launching so a guardian restart cannot reset the limit.
                self.proxyRecovery.reserve(now:now)
                do {try privateWrite(JSONEncoder().encode(self.proxyRecovery),self.recoveryStatePath)}
                catch {self.proxyRecoveryStatus="无法保存自动恢复次数，未启动 Surge；请手动打开。";self.publish();return}
                self.recoveryChecking=true
                self.proxyRecoveryStatus="Surge 已退出，正在校验程序并尝试启动一次；原出口验证前保持阻断。"
                self.record("proxy_recovery_attempt","固定代理端口不可用且 Surge 未运行，尝试启动一次")
                self.publish()
                DispatchQueue.global(qos:.utility).async { [weak self] in
                    let trusted=trustedSurgeApplication()
                    DispatchQueue.main.async { [weak self] in
                        guard let self=self else{return}
                        let allowed=self.q.sync {trusted && !self.paused && !self.sleeping && !self.isOpen && self.configurationIssue()==nil && !FileManager.default.fileExists(atPath:self.c.stateDirectory+"/paused")}
                        guard allowed else {
                            self.q.async {self.recoveryChecking=false;self.proxyRecoveryStatus=trusted ? "自动启动已取消，以当前暂停或检测状态为准。":"Surge 官方程序签名未通过，未自动启动；请核对安装。";self.publish()}
                            return
                        }
                        // No restart, profile switch, node change or forced foreground focus.
                        if NSRunningApplication.runningApplications(withBundleIdentifier:surgeBundleID).contains(where:{!$0.isTerminated}) {
                            self.q.async {self.recoveryChecking=false;self.proxyRecoveryStatus="Surge 已在启动，等待固定端口和原出口验证。";self.publish()};return
                        }
                        let options=NSWorkspace.OpenConfiguration();options.activates=false
                        NSWorkspace.shared.openApplication(at:surgeApplicationURL,configuration:options) { [weak self] _,error in
                            self?.q.async { [weak self] in
                                guard let self=self else{return}
                                self.recoveryChecking=false
                                self.proxyRecoveryStatus=self.isOpen ? "":error == nil ? "已请求启动 Surge，等待固定端口和原出口验证；尚未凭启动结果放行。":"无法启动 Surge，请手动打开并检查服务。"
                                self.record("proxy_recovery_result",error == nil ? "启动请求已完成，仍以出口核验决定放行":"Surge 启动请求失败")
                                self.publish()
                            }
                        }
                    }
                }
            }
        }
    }
    func setPaused(_ value:Bool) {
        q.async {
            let path=self.c.stateDirectory+"/paused"
            do {
                if value { try privateWrite(Data("manual\n".utf8),path) }
                else if FileManager.default.fileExists(atPath:path) { try FileManager.default.removeItem(atPath:path) }
            } catch { self.block("无法保存手动断开状态"); return }
            let changed=self.paused != value;self.paused=value
            if changed {self.block(value ? "已手动断开 Claude 网络" : "正在重新验证出口");self.lastProbeStarted = -100}
            self.probe()
        }
    }
    func sleep(_ value:Bool) {
        q.async { self.sleeping=value; self.block(value ? "电脑休眠，连接已关闭" : "唤醒后重新验证出口"); self.lastProbeStarted = -100; if !value { self.probe() } }
    }
    func snapshot() -> [String:Any] {
        ["version":"1.3.0","pid":Int(getpid()),"open":isOpen,"reason":reason,"activeTunnels":tunnels.count,
         "proxyRecoveryStatus":proxyRecoveryStatus,"automaticProxyRecovery":usesSurge,
         "probeResult":probeResult,"updatedAt":ISO8601DateFormatter().string(from:Date()),
         "port":Int(c.port),"upstreamPort":Int(c.upstreamPort),"paused":paused,
         "claudeLegacyConnections":legacyConnections,"claudeGuardedConnections":guardedConnections,
         "coverage":"仅覆盖已使用保护入口的连接；不代表零封号风险",
         "probeIntervalSeconds":sensitivity.interval,"probeTimeoutSeconds":sensitivity.timeout,"healthLeaseSeconds":sensitivity.lease,
         "tunnelHandshakeTimeoutSeconds":Tunnel.upstreamHandshakeTimeout,"codeSettingsMonitored":c.codeSettings != nil,
         "degraded":degraded,"transientFailures":transientFailures,"transientGraceSeconds":sensitivity.grace,
         "lastGoodAgeSeconds":lastGood>0 ? max(0,ProcessInfo.processInfo.systemUptime-lastGood):-1,"sensitivity":"balanced"]
    }
    func checkCoverage() {
        coverageRunning=true; lastCoverage=ProcessInfo.processInfo.systemUptime
        let p=Process(); p.executableURL=URL(fileURLWithPath:"/usr/sbin/lsof")
        p.arguments=["-nP","-iTCP","-sTCP:ESTABLISHED","-Fpcn"]
        p.environment=["PATH":"/usr/bin:/bin:/usr/sbin"]
        let out=Pipe(); p.standardOutput=out; p.standardError=FileHandle.nullDevice
        DispatchQueue.global(qos:.utility).async { [weak self] in
            guard let self=self else { return }
            var old=0, guarded=0
            do {
                try p.run()
                DispatchQueue.global().asyncAfter(deadline:.now()+4) { if p.isRunning { p.terminate() } }
                let data=out.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
                if p.terminationStatus != 0 && p.terminationStatus != 1 { old = -1; guarded = -1 }
                else {
                    var selected=false
                    for line in (String(data:data,encoding:.utf8) ?? "").split(separator:"\n") {
                        if line.hasPrefix("p") { selected=false }
                        if line.hasPrefix("c") { selected=String(line.dropFirst()).lowercased().hasPrefix("claude") && !line.contains("Shield") }
                        if selected && line.hasPrefix("n") {
                            if line.hasSuffix("->127.0.0.1:\(self.c.upstreamPort)") { old += 1 }
                            if line.hasSuffix("->127.0.0.1:\(self.c.port)") { guarded += 1 }
                        }
                    }
                }
            } catch { old = -1; guarded = -1 }
            let oldCount=old, guardedCount=guarded
            self.q.async { self.legacyConnections=oldCount; self.guardedConnections=guardedCount; self.coverageRunning=false; self.publish() }
        }
    }
    func publish() {
        let s=snapshot()
        if let d=try? JSONSerialization.data(withJSONObject:s,options:[.prettyPrinted,.sortedKeys]) { try? privateWrite(d,c.stateDirectory+"/status.json") }
        if let callback=onChange { DispatchQueue.main.async { callback(s) } }
    }
    func record(_ event:String,_ message:String) {
        let path=c.stateDirectory+"/events.jsonl"
        let attrs=try? FileManager.default.attributesOfItem(atPath:path)
        if (attrs?[.size] as? Int ?? 0)>262144 {
            try? FileManager.default.removeItem(atPath:path+".1")
            try? FileManager.default.moveItem(atPath:path,toPath:path+".1")
        }
        let obj=["at":ISO8601DateFormatter().string(from:Date()),"event":event,"message":message]
        guard var d=try? JSONSerialization.data(withJSONObject:obj,options:.sortedKeys) else { return }; d.append(10)
        if !FileManager.default.fileExists(atPath:path) { try? privateWrite(Data(),path) }
        if let h=FileHandle(forWritingAtPath:path) { _=try? h.seekToEnd(); try? h.write(contentsOf:d); try? h.close() }
    }
}

func selfTest(_ c:Configuration) -> (Int,[String]) {
    var failures=[String](); var n=0
    func check(_ ok:Bool,_ name:String) { n += 1; if !ok { failures.append(name) } }
    check(authority(Data("CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443".utf8)) == "api.anthropic.com:443","valid CONNECT")
    for bad in ["GET https://example.com/ HTTP/1.1","CONNECT user:pw@example.com:443 HTTP/1.1","CONNECT example.com:80 HTTP/1.1","CONNECT example.com:443 HTTP/2","CONNECT example.com:443 HTTP/1.1\0","CONNECT example.com:443@evil:443 HTTP/1.1"] { check(authority(Data(bad.utf8)) == nil,"reject unsafe header") }
    let now=Date().timeIntervalSince1970
    let body="ip=\(c.expectedIP)\nloc=\(c.expectedCountry)\nts=\(now)\n"
    check(traceCheck(body,c,now:now) == nil,"valid trace")
    check(traceCheck(body.replacingOccurrences(of:c.expectedIP,with:"0.0.0.0"),c,now:now) != nil,"IP drift")
    check(traceCheck(body.replacingOccurrences(of:"loc=\(c.expectedCountry)",with:"loc=ZZ"),c,now:now) != nil,"country drift")
    check(traceCheck(body,c,now:now+120) != nil,"stale trace")
    check(traceCheck(body+"ip=\(c.expectedIP)\n",c,now:now) != nil,"duplicate trace")
    check(traceCheck("",c,now:now) != nil,"empty trace")
    let policy=Sensitivity(scale:1)
    check(!policy.shouldBlock(failures:1,age:31),"one failed round cannot trip transient breaker")
    check(!policy.shouldBlock(failures:3,age:29),"three failures still honor grace window")
    check(policy.shouldBlock(failures:3,age:30),"persistent failures trip after grace")
    check(policy.lease==45 && policy.timeout==12 && policy.connectTimeout==8 && policy.interval==10,"production timing")
    check(Tunnel.upstreamHandshakeTimeout==12,"business CONNECT deadline remains twelve seconds in accelerated lab")
    var recovery=ProxyRecoveryState()
    func mayRecover(_ code:Int32=7,_ enabled:Bool=true,_ running:Bool=false,_ paused:Bool=false,_ configured:Bool=true,_ now:Double=1000)->Bool {
        recovery.canAttempt(now:now,curlCode:code,enabled:enabled,appRunning:running,paused:paused,configurationOK:configured)
    }
    check(mayRecover(),"missing proxy can request one launch")
    check(!mayRecover(28),"timeout never restarts proxy")
    check(!mayRecover(60),"TLS failure never restarts proxy")
    check(!mayRecover(7,false),"unconfigured or lab provider cannot launch")
    check(!mayRecover(7,true,true),"running proxy is never restarted")
    check(!mayRecover(7,true,false,true),"manual pause prevents automatic launch")
    check(!mayRecover(7,true,false,false,false),"configuration drift prevents automatic launch")
    recovery.reserve(now:1000)
    check(!mayRecover(7,true,false,false,true,2000),"one attempt per unresolved outage even after cooldown")
    recovery.verified()
    check(!mayRecover(7,true,false,false,true,1599),"new outage honors ten minute cooldown")
    check(!mayRecover(7,true,false,false,true,900),"clock rollback cannot bypass cooldown")
    check(mayRecover(7,true,false,false,true,1600),"verified recovery permits a later outage attempt after cooldown")
    recovery.reserve(now:1600)
    let restored=(try? JSONEncoder().encode(recovery)).flatMap{try? JSONDecoder().decode(ProxyRecoveryState.self,from:$0)}
    check(restored?.attemptedThisOutage==true && restored?.lastAttempt==1600,"recovery attempt survives serialization and service restart")
    if case .transient=verdict("",c,fallback:false,now:now){check(true,"missing primary IP is not proof of drift")}else{check(false,"missing primary IP is not proof of drift")}
    if case .good=verdict("{\"ip\":\"\(c.expectedIP)\"}",c,fallback:true,now:now){check(true,"fallback requires original IP")}else{check(false,"fallback requires original IP")}
    if case .unsafe=verdict("{\"ip\":\"203.0.113.222\"}",c,fallback:true,now:now){check(true,"fallback cannot trust changed IP")}else{check(false,"fallback cannot trust changed IP")}
    return (n,failures)
}

final class MenuApp:NSObject, NSApplicationDelegate {
    let gate:Gate
    var item:NSStatusItem!
    var statusLine:NSMenuItem!
    var countLine:NSMenuItem!
    var latest=[String:Any]()
    init(_ gate:Gate) { self.gate=gate }
    func applicationDidFinishLaunching(_ notification:Notification) {
        NSApp.setActivationPolicy(.accessory)
        item=NSStatusBar.system.statusItem(withLength:NSStatusItem.variableLength)
        let menu=NSMenu()
        statusLine=NSMenuItem(title:"Claude：启动检查中",action:nil,keyEquivalent:""); menu.addItem(statusLine)
        countLine=NSMenuItem(title:"经过保护入口的连接：0",action:nil,keyEquivalent:""); menu.addItem(countLine)
        menu.addItem(.separator())
        for (title,selector) in [("查看保护状态与范围",#selector(showStatus)),("立即检查／恢复连接",#selector(recheck)),("立即断开 Claude 网络",#selector(disconnect)),("运行不影响任务的自检",#selector(runTests)),("查看本机维护记录",#selector(showLogs))] {
            let entry=NSMenuItem(title:title,action:selector,keyEquivalent:""); entry.target=self; menu.addItem(entry)
        }
        menu.addItem(.separator())
        menu.addItem(NSMenuItem(title:"登录自动运行 · 无需专用 Claude 入口",action:nil,keyEquivalent:""))
        item.menu=menu; item.button?.title="◌ Claude"
        gate.onChange = { [weak self] s in self?.update(s) }
        NSWorkspace.shared.notificationCenter.addObserver(self,selector:#selector(willSleep),name:NSWorkspace.willSleepNotification,object:nil)
        NSWorkspace.shared.notificationCenter.addObserver(self,selector:#selector(didWake),name:NSWorkspace.didWakeNotification,object:nil)
        do { try gate.start() } catch { alert("保护启动失败","保护端口不可用，未开放连接。请检查是否已经运行另一份保护程序。"); NSApp.terminate(nil) }
    }
    func update(_ s:[String:Any]) {
        latest=s; let open=s["open"] as? Bool ?? false
        let old=s["claudeLegacyConnections"] as? Int ?? -1
        item.button?.title = !open ? "⛔ Claude" : old>0 ? "⚠ Claude" : s["degraded"] as? Bool == true ? "◐ Claude":"● Claude"
        item.button?.toolTip=s["reason"] as? String
        statusLine.title = open && old>0 ? "闸门就绪 · 旧任务仍需重启接管" : "Claude：\(s["reason"] as? String ?? "未知")"
        countLine.title="经过保护入口的连接：\(s["activeTunnels"] as? Int ?? 0)"
    }
    func alert(_ title:String,_ body:String) {
        let a=NSAlert(); a.messageText=title; a.informativeText=body; a.addButton(withTitle:"知道了")
        NSApp.activate(ignoringOtherApps:true); a.runModal()
    }
    @objc func showStatus() {
        alert("Claude 连接保护", "状态：\(latest["reason"] as? String ?? "检查中")\n检测：\(latest["probeResult"] as? String ?? "尚未完成")\nClaude 旧入口连接：\(latest["claudeLegacyConnections"] as? Int ?? -1)\nClaude 保护入口连接：\(latest["claudeGuardedConnections"] as? Int ?? -1)\n（-1 表示尚未取得快照；连接计数不等于所有网络已覆盖。）\n\n约每 10 秒检查固定出口；主检测失败会用备用 HTTPS 服务确认原 IP。单次超时 12 秒；连续至少 3 轮失败且 30 秒无有效结果才断开，45 秒为最长未验证窗口。明确 IP／地区变化、证书或配置异常仍立即阻断。恢复只需一次当前有效核验通过；不再等待连续两轮成功。\n\n只接管重启后使用保护入口的本机 Claude 连接。外部浏览器、远程 Code、绕过代理的命令和系统更新不受此闸门完整控制。\n\n它不检测账户处罚，不保证不封号，也不改变账号历史或地区资格。")
    }
    @objc func recheck() { gate.setPaused(false) }
    @objc func disconnect() { gate.setPaused(true) }
    @objc func runTests() {
        let result=selfTest(gate.c)
        alert("本机自检",result.1.isEmpty ? "\(result.0) 项解析与风险判定自检通过。\n\n此按钮不制造真实断网，不中断任务；当前出口检测结果见保护状态。安装前另有独立端口故障测试。" : "自检失败：\(result.1.joined(separator:", "))")
    }
    @objc func showLogs() { NSWorkspace.shared.open(URL(fileURLWithPath:gate.c.stateDirectory)) }
    @objc func willSleep() { gate.sleep(true) }
    @objc func didWake() { gate.sleep(false) }
}

umask(0o077)
let args=CommandLine.arguments
func option(_ name:String) -> String? { guard let i=args.firstIndex(of:name), args.count>i+1 else { return nil }; return args[i+1] }
let defaultConfig=FileManager.default.homeDirectoryForCurrentUser.path+"/Library/Application Support/ClaudeConnectionGuard/shield/config.json"
let configPath=option("--config") ?? defaultConfig
do {
    let c=try JSONDecoder().decode(Configuration.self,from:Data(contentsOf:URL(fileURLWithPath:configPath)))
    if args.contains("--self-test") {
        let result=selfTest(c); print("self-test: \(result.0-result.1.count)/\(result.0)"); exit(result.1.isEmpty ? 0:1)
    }
    let gate=try Gate(c,path:configPath,lab:args.contains("--lab"),fastLab:args.contains("--lab-fast"))
    if args.contains("--headless") { try gate.start(); dispatchMain() }
    let app=NSApplication.shared
    let delegate=MenuApp(gate); app.delegate=delegate; app.run()
} catch {
    fputs("Claude protection could not load its private configuration; no connection was opened.\n",stderr); exit(2)
}
