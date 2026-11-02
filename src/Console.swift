import Foundation
import Network
import CryptoKit
import Darwin

let args=CommandLine.arguments
func option(_ key:String)->String? { if let i=args.firstIndex(of:key), args.count>i+1 { return args[i+1] }; return nil }
let base=option("--base") ?? FileManager.default.homeDirectoryForCurrentUser.path+"/Library/Application Support/ClaudeConnectionGuard/shield"
let port=UInt16(option("--port") ?? "17900")!
let htmlPath=option("--html") ?? base+"/console/index.html"
let queue=DispatchQueue(label:"local.claude.shield.console")
let csrf=UUID().uuidString+UUID().uuidString
let nonce=UUID().uuidString.replacingOccurrences(of:"-",with:"")
umask(0o077)

func json(_ path:String)->[String:Any]? {
    guard let d=try? Data(contentsOf:URL(fileURLWithPath:path)) else { return nil }
    return (try? JSONSerialization.jsonObject(with:d)) as? [String:Any]
}
func hashFile(_ path:String)->String? {
    guard let d=try? Data(contentsOf:URL(fileURLWithPath:path)) else { return nil }
    return SHA256.hash(data:d).map { String(format:"%02x",$0) }.joined()
}
func stamp()->String { ISO8601DateFormatter().string(from:Date()) }
func run(_ executable:String,_ arguments:[String],seconds:Double=12)->(Int32,String) {
    let p=Process(); p.executableURL=URL(fileURLWithPath:executable); p.arguments=arguments
    p.environment=["PATH":"/usr/bin:/bin:/usr/sbin","LANG":"C"]
    let out=Pipe(); p.standardOutput=out; p.standardError=FileHandle.nullDevice
    do {
        try p.run()
        DispatchQueue.global().asyncAfter(deadline:.now()+seconds) { if p.isRunning { p.terminate() } }
        let d=out.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
        return (p.terminationStatus,String(data:d,encoding:.utf8) ?? "")
    } catch { return (-1,"") }
}
func row(_ title:String,_ status:String,_ detail:String)->[String:String] { ["title":title,"status":status,"detail":detail] }
var audit=[String:Any]()
var checking=false
var lastCheck:Double = -100

func codeProxyRow(_ c:[String:Any])->[String:String] {
    guard let path=c["codeSettings"] as? String, !path.isEmpty else {
        return row("Code 固定代理配置","unknown","尚未纳入用户级 Code 代理检查；桌面客户端的代理配置不代表 Code 会话已经接入。")
    }
    guard let settings=json(path), let env=settings["env"] as? [String:Any] else {
        return row("Code 固定代理配置","fail","用户级 Code 设置缺失、无法读取或未配置代理环境变量。")
    }
    let expected="http://127.0.0.1:\(c["port"] as? Int ?? 0)"
    let proxyKeys=["HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","http_proxy","https_proxy","all_proxy"]
    let loopback:Set<String>=["localhost","127.0.0.1","::1"]
    let invalid=proxyKeys.filter { env[$0] as? String != expected } + ["NO_PROXY","no_proxy"].filter {
        guard let value=env[$0] as? String else { return true }
        let hosts=value.components(separatedBy:",").map{$0.trimmingCharacters(in:.whitespacesAndNewlines)}
        return hosts.count != loopback.count || Set(hosts) != loopback
    }
    // Report variable names only: a changed value might contain credentials.
    if !invalid.isEmpty { return row("Code 固定代理配置","fail","以下变量缺失或偏离保护入口：\(invalid.joined(separator:", "))。绕过列表仅允许既定本机地址。") }
    return row("Code 固定代理配置","pass","用户级设置中的大小写代理变量均指向保护入口，绕过列表仅含本机地址。配置通过不等于所有运行会话已接管；已有会话、项目覆盖和远程任务仍需分别核验。")
}
func dnsRows(_ c:[String:Any])->[[String:String]] {
    var rows=[row("守护的域名处理","unknown","守护将 CONNECT 目标域名传给上游代理，不在本机解析该目标。此项说明实现边界，未证明代理上游、浏览器或所有 DNS／UDP 流量均受保护。")]
    guard let baseline=(c["baselines"] as? [[String:String]] ?? []).first(where:{ (($0["name"] ?? "")+" "+($0["path"] ?? "")).lowercased().contains("surge") }) else { return rows }
    guard let source=try? String(contentsOfFile:baseline["path"] ?? "",encoding:.utf8) else {
        rows.append(row("Surge 加密 DNS 配置","warn","无法读取维护源，尚未核验加密 DNS 配置。")); return rows
    }
    var section="", values=[String:String](), duplicates=Set<String>()
    for raw in source.components(separatedBy:.newlines) {
        let line=String(raw.split(separator:"#",maxSplits:1,omittingEmptySubsequences:false)[0]).trimmingCharacters(in:.whitespaces)
        if line.hasPrefix("[") { section=line.lowercased(); continue }
        guard section=="[general]", let equal=line.firstIndex(of:"=") else { continue }
        let key=line[..<equal].trimmingCharacters(in:.whitespaces).lowercased()
        guard ["encrypted-dns-server","encrypted-dns-follow-outbound-mode"].contains(key) else { continue }
        if values[key] != nil { duplicates.insert(key) }
        values[key]=line[line.index(after:equal)...].trimmingCharacters(in:.whitespaces)
    }
    let servers=(values["encrypted-dns-server"] ?? "").split(separator:",").map{$0.trimmingCharacters(in:.whitespaces)}
    let encrypted = !servers.isEmpty && servers.allSatisfy { value in
        guard let u=URLComponents(string:value), let scheme=u.scheme?.lowercased(), let host=u.host else { return false }
        return ["https","h3","tls","quic"].contains(scheme) && !host.isEmpty
    }
    let follows=values["encrypted-dns-follow-outbound-mode"]?.lowercased()=="true"
    let declared=encrypted && follows && duplicates.isEmpty
    let detail=declared ? "维护源已声明加密 DNS 并跟随出站规则。这里只核验配置，未证明运行中的规则、代理启动解析及所有 DNS 流量均无绕行。":"维护源未完整声明加密 DNS 与跟随出站规则，或存在重复配置；普通 DNS 可能仍经系统或本地网络解析。"
    rows.append(row("Surge 加密 DNS 配置",declared ? "pass":"warn",detail))
    return rows
}

func configRows(_ c:[String:Any])->[[String:String]] {
    var rows=[[String:String]]()
    let native=json(c["nativeConfig"] as? String ?? "")
    let meta=json(c["nativeMeta"] as? String ?? "")
    let good=native?["egressProxyUrl"] as? String == "http://127.0.0.1:\(c["port"] as? Int ?? 0)" && native?["egressProxyPacUrl"] == nil && meta?["appliedId"] as? String == c["nativeID"] as? String
    rows.append(row("Claude 固定代理入口",good ? "pass":"fail",good ? "配置指向本机保护入口，未启用 PAC 回退。":"代理地址或当前配置选择偏离保护基线。"))
    rows.append(codeProxyRow(c))
    for b in c["baselines"] as? [[String:String]] ?? [] {
        let good=hashFile(b["path"] ?? "") == b["sha256"] && b["sha256"] != nil
        rows.append(row(b["name"] ?? "固定代理规则",good ? "pass":"fail",good ? "维护源与已确认基线一致。":"维护源缺失或发生改动；需核实，不能直接重新信任。"))
    }
    rows.append(contentsOf:dnsRows(c))
    return rows
}
func snapshot()->[String:Any] {
    let c=json(base+"/config.json") ?? [:]
    var s=json(base+"/state/status.json") ?? [:]
    let time=ISO8601DateFormatter().date(from:s["updatedAt"] as? String ?? "") ?? .distantPast
    let age=Date().timeIntervalSince(time)
    let pid=s["pid"] as? Int ?? 0
    let live=pid>0 && kill(Int32(pid),0)==0 && age>=(-5) && age<16
    s["serviceFresh"]=live; s["ageSeconds"]=max(0,Int(min(999999,age)))
    if !live { s["open"]=false; s["reason"]="保护服务未响应，状态已过期" }
    let baselineNames=(c["baselines"] as? [[String:String]] ?? []).map{($0["name"] ?? "")+" "+($0["path"] ?? "")}.joined(separator:" ").lowercased()
    s["proxyName"]=baselineNames.contains("surge") ? "Surge":baselineNames.contains("clash") ? "Clash Verge":"固定代理"
    s["expectedIP"]=c["expectedIP"] ?? "未配置"
    s["expectedCountry"]=c["expectedCountry"] ?? "—"
    s["checking"]=checking; s["audit"]=audit
    s["configurationChecks"]=configRows(c)
    let path=base+"/state/events.jsonl"
    if let text=try? String(contentsOfFile:path,encoding:.utf8) {
        s["events"]=text.split(separator:"\n").suffix(16).reversed().compactMap { line -> [String:Any]? in
            guard let d=String(line).data(using:.utf8) else { return nil }; return (try? JSONSerialization.jsonObject(with:d)) as? [String:Any]
        }
    }
    s["consoleVersion"]="1.3.0"
    return s
}
func beginAudit() {
    guard !checking, ProcessInfo.processInfo.systemUptime-lastCheck>=5 else { return }
    checking=true; lastCheck=ProcessInfo.processInfo.systemUptime
    let initial=snapshot()
    DispatchQueue.global(qos:.utility).async {
        let c=json(base+"/config.json") ?? [:]
        var rows=configRows(c)
        let fresh=initial["serviceFresh"] as? Bool ?? false
        rows.append(row("连接保护服务",fresh ? "pass":"fail",fresh ? "进程存在，状态更新未过期。":"保护服务没有提供近期有效状态。"))
        let origin=initial["claudeLegacyConnections"] as? Int ?? -1
        let guarded=initial["claudeGuardedConnections"] as? Int ?? -1
        rows.append(row("Claude 实际接入",origin>0 ? "warn":guarded>0 ? "pass":"unknown",origin>0 ? "仍有 \(origin) 条旧入口连接，保存任务后重启 Claude 才能接管。":guarded>0 ? "观察到 \(guarded) 条保护入口连接，旧入口连接为 0；这不能证明覆盖所有进程。":"当前没有足够连接样本；可能尚未打开 Claude 或处于空闲。"))
        let expected=c["expectedIP"] as? String ?? ""
        let upstream=c["upstreamPort"] as? Int ?? 0
        let start=Date()
        let probeArgs=["-q","--silent","--show-error","--fail","--connect-timeout","8","--max-time","12","--max-filesize","8192","--proto","=https","--http1.1","--proxy","http://127.0.0.1:\(upstream)","--noproxy",""]
        let probe=run("/usr/bin/curl",probeArgs+["https://www.cloudflare.com/cdn-cgi/trace"],seconds:14)
        var trace=[String:String]()
        for line in probe.1.split(separator:"\n") { let parts=line.split(separator:"=",maxSplits:1); if parts.count==2 { trace[String(parts[0])]=String(parts[1]) } }
        let timestamp=Double(trace["ts"] ?? "") ?? 0
        var match=probe.0==0 && trace["ip"]==expected && trace["loc"]==c["expectedCountry"] as? String && abs(timestamp-Date().timeIntervalSince1970)<60
        var unsafe=[51,60,77,90,91].contains(probe.0) || (probe.0==0 && trace["ip"] != nil && trace["loc"] != nil && abs(timestamp-Date().timeIntervalSince1970)<60 && !match)
        var detail=match ? "独立检测经固定住宅代理链成功，IP、地区、TLS 和时间符合基线。":"本次主、备用检测未确认出口；这不是一次失败就断网的判据，后台会继续按缓冲策略核验。"
        if !match && !unsafe {
            let backup=run("/usr/bin/curl",probeArgs+["https://api.ipify.org?format=json"],seconds:14)
            let ip=(backup.1.data(using:.utf8).flatMap{try? JSONSerialization.jsonObject(with:$0)} as? [String:Any])?["ip"] as? String
            match=backup.0==0 && ip==expected
            unsafe=[51,60,77,90,91].contains(backup.0) || (backup.0==0 && ip != nil && ip != expected)
            if match {trace["ip"]=ip;trace.removeValue(forKey:"loc");detail="主检测暂不可用；备用 HTTPS 服务确认仍为原固定 IP，不另作实时地区判定。"}
        }
        if unsafe {detail="独立检测发现出口与基线不符或证书校验失败，请查看后台阻断原因。"}
        rows.append(row("真实出口与 HTTPS 校验",match ? "pass":unsafe ? "fail":"warn",detail))
        let latency=Int(Date().timeIntervalSince(start)*1000)
        let requirement="-R=anchor apple generic and certificate leaf[subject.OU] = \"Q6L2SF6YDW\""
        let signature=run("/usr/bin/codesign",["--verify","--deep","--strict",requirement,"/Applications/Claude.app"],seconds:20)
        rows.append(row("Claude 官方程序签名",signature.0==0 ? "pass":"warn",signature.0==0 ? "当前程序通过完整性和 Anthropic 签名要求检查。":"本次签名核验未通过或未完成；需进一步核对，不能直接判定恶意程序。"))
        for (label,title) in [("local.claudeshield.claude-shield","保护工具登录启动"),("local.claudeshield.claude-shield-console","管理页面登录启动")] {
            let r=run("/bin/launchctl",["print","gui/\(getuid())/\(label)"],seconds:5)
            let good=r.0==0 && r.1.contains("state = running")
            rows.append(row(title,good ? "pass":"warn",good ? "本机用户登录服务已载入并运行。":"未验证到运行中的登录服务。"))
        }
        let permissions=json(FileManager.default.homeDirectoryForCurrentUser.path+"/.claude/settings.json")?["permissions"] as? [String:Any]
        let bypass=permissions?["defaultMode"] as? String == "bypassPermissions"
        rows.append(row("Code 权限边界",bypass ? "warn":"unknown",bypass ? "保留你选择的跳过确认模式。它不是封号证据，但执行的命令可能主动绕开代理或修改保护工具。":"权限需结合具体会话和项目配置判断，本检查不修改权限。"))
        let firewall=run("/usr/libexec/ApplicationFirewall/socketfilterfw",["--getglobalstate"],seconds:5)
        let enabled=firewall.0==0 && firewall.1.lowercased().contains("enabled")
        rows.append(row("系统入站防火墙",enabled ? "pass":"warn",enabled ? "当前入站防火墙已开启；它不等于出站防泄漏。":"未确认入站防火墙开启。属于主机安全项，不是 Claude 封号证据。"))
        rows.append(row("远程任务与外部浏览器","unknown","云端／SSH、ego lite、BrowserOS、更新器及绕开代理的命令不由此闸门完整接管。"))
        rows.append(row("账号、付款与地区资格","unknown","成品号交接前历史、原付款方和服务地区资格无法由本机工具验证或修复。"))
        rows.append(row("IP 信誉与独享情况","unknown","IP 相同不证明独享或信誉良好；本工具不会伪造信誉评分。"))
        let result:[String:Any]=["completedAt":stamp(),"checks":rows,"observedIP":trace["ip"] ?? "未取得","observedCountry":trace["loc"] ?? "未取得","latencyMs":latency,"exitMatches":match]
        queue.async {
            audit=result; checking=false
            if let d=try? JSONSerialization.data(withJSONObject:result,options:[.prettyPrinted,.sortedKeys]) { try? d.write(to:URL(fileURLWithPath:base+"/console/last-audit.json"),options:.atomic) }
        }
    }
}

final class Request {
    let connection:NWConnection
    var buffer=Data()
    var finished=false
    init(_ c:NWConnection) { connection=c }
    func start() {
        connection.start(queue:queue); receive()
        queue.asyncAfter(deadline:.now()+6) { [self] in if !finished { close() } }
    }
    func close() { finished=true; connection.cancel() }
    func receive() {
        connection.receive(minimumIncompleteLength:1,maximumLength:8192) { [self] data,_,end,error in
            if finished { return }
            if let data=data { buffer.append(data) }
            if buffer.count>16384 { respond(413,Data()); return }
            if let range=buffer.range(of:Data("\r\n\r\n".utf8)) {
                guard let text=String(data:buffer.subdata(in:0..<range.lowerBound),encoding:.utf8) else { respond(400,Data()); return }
                let lines=text.components(separatedBy:"\r\n"); let first=lines[0].split(separator:" ")
                guard first.count==3,first[2]=="HTTP/1.1" || first[2]=="HTTP/1.0" else { respond(400,Data());return }
                var headers=[String:String]()
                for line in lines.dropFirst() {
                    guard let colon=line.firstIndex(of:":"),line.first != " ",line.first != "\t" else { respond(400,Data());return }
                    let key=line[..<colon].lowercased(); if headers[key] != nil { respond(400,Data());return }
                    headers[key]=line[line.index(after:colon)...].trimmingCharacters(in:.whitespaces)
                }
                guard ["127.0.0.1:\(port)","localhost:\(port)"].contains(headers["host"] ?? "") else { respond(403,Data());return }
                if let origin=headers["origin"], !["http://127.0.0.1:\(port)","http://localhost:\(port)"].contains(origin) { respond(403,Data());return }
                guard headers["transfer-encoding"] == nil else { respond(400,Data());return }
                let count=Int(headers["content-length"] ?? "0") ?? -1
                guard count>=0,count<=1024 else { respond(413,Data());return }
                if buffer.count-range.upperBound<count { if end || error != nil { close() } else { receive() };return }
                handle(String(first[0]),String(first[1]),headers)
            } else if end || error != nil { close() } else { receive() }
        }
    }
    func handle(_ method:String,_ path:String,_ h:[String:String]) {
        if method=="GET" && path=="/" {
            guard var text=try? String(contentsOfFile:htmlPath,encoding:.utf8) else { respond(503,Data());return }
            text=text.replacingOccurrences(of:"__CSRF__",with:csrf).replacingOccurrences(of:"__NONCE__",with:nonce)
            respond(200,Data(text.utf8),type:"text/html; charset=utf-8");return
        }
        if method=="GET" && path=="/api/status" { respondJSON(200,snapshot());return }
        if method=="POST" && ["/api/check","/api/pause","/api/resume"].contains(path) {
            guard h["x-shield-token"]==csrf,
                  ["http://127.0.0.1:\(port)","http://localhost:\(port)"].contains(h["origin"] ?? "") else { respond(403,Data());return }
            if path=="/api/check" { beginAudit(); respondJSON(202,["accepted":true]);return }
            let pause=base+"/state/paused"
            do {
                if path=="/api/pause" { try Data("manual\n".utf8).write(to:URL(fileURLWithPath:pause),options:.atomic) }
                else if FileManager.default.fileExists(atPath:pause) { try FileManager.default.removeItem(atPath:pause) }
            } catch { respondJSON(500,["error":"无法保存状态，未宣称操作成功"]);return }
            respondJSON(202,["accepted":true]);return
        }
        respond(404,Data())
    }
    func respondJSON(_ code:Int,_ body:[String:Any]) {
        respond(code,(try? JSONSerialization.data(withJSONObject:body,options:.sortedKeys)) ?? Data("{}".utf8))
    }
    func respond(_ code:Int,_ data:Data,type:String="application/json; charset=utf-8") {
        guard !finished else { return }; finished=true
        let headers="HTTP/1.1 \(code) Response\r\nContent-Type: \(type)\r\nContent-Length: \(data.count)\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; script-src 'nonce-\(nonce)'; style-src 'nonce-\(nonce)'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'\r\n\r\n"
        connection.send(content:Data(headers.utf8)+data,completion:.contentProcessed { [self] _ in connection.cancel() })
    }
}

do {
    let p=NWParameters.tcp;p.requiredLocalEndpoint = .hostPort(host:"127.0.0.1",port:NWEndpoint.Port(rawValue:port)!)
    p.allowLocalEndpointReuse=false
    let listener=try NWListener(using:p)
    listener.newConnectionHandler = { c in Request(c).start() }
    listener.stateUpdateHandler = { state in if case .failed = state { exit(2) } }
    listener.start(queue:queue)
    dispatchMain()
} catch { fputs("Console did not open a listening port.\n",stderr);exit(2) }
