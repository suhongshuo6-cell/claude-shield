from pathlib import Path
import platform,plistlib,shutil,subprocess
r=Path(__file__).resolve().parent;b=r/'build';b.mkdir(exist_ok=True)
for source,binary,frameworks in [('main.swift','ClaudeShield',['AppKit','Network','CryptoKit','Security']),('Console.swift','ClaudeShieldConsole',['Network','CryptoKit'])]:
 cmd=['xcrun','swiftc','-swift-version','5','-O','-module-cache-path',str(b/'module-cache'),str(r/'src'/source),'-o',str(b/binary)]
 for f in frameworks:cmd+=['-framework',f]
 subprocess.run(cmd,check=True)
app=b/'Claude连接保护.app';contents=app/'Contents';(contents/'MacOS').mkdir(parents=True,exist_ok=True)
shutil.copy2(b/'ClaudeShield',contents/'MacOS/ClaudeShield')
(contents/'Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier':'local.claudeshield.ClaudeShield','CFBundleExecutable':'ClaudeShield','CFBundleName':'Claude连接保护','CFBundleDisplayName':'Claude连接保护','CFBundlePackageType':'APPL','CFBundleShortVersionString':'1.3.0','CFBundleVersion':'8','LSUIElement':True,'LSMinimumSystemVersion':platform.mac_ver()[0],'NSHighResolutionCapable':True}))
subprocess.run(['/usr/bin/codesign','--force','--sign','-','--identifier','local.claudeshield.ClaudeShield',str(app)],check=True)
# Tests execute exactly the signed binary delivered inside the app bundle.
shutil.copy2(contents/'MacOS/ClaudeShield',b/'ClaudeShield')
