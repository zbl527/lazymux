## lazymux.py - Lazymux v4.0
##
import os, sys
import readline
from time import sleep as timeout
from core.lzmcore import *

def main():
    banner()
    print("   [01] 信息收集")
    print("   [02] 漏洞分析")
    print("   [03] 网络黑客攻击")
    print("   [04] 数据库评估")
    print("   [05] 密码攻击")
    print("   [06] 无线攻击")
    print("   [07] 逆向工程")
    print("   [08] 利用工具")
    print("   [09] 嗅探与欺骗")
    print("   [10] 报告工具")
    print("   [11] 取证工具")
    print("   [12] 压力测试")
    print("   [13] 安装Linux发行版")
    print("   [14] Termux工具")
    print("   [15] Shell功能[.bashrc]")
    print("   [16] 安装CLI游戏")
    print("   [17] 恶意软件分析")
    print("   [18] 编译器/解释器")
    print("   [19] 社会工程学工具")

    print("\n   [99] 更新Lazymux")
    print("   [00] 退出Lazymux\n")
    lazymux = input("lzmx > set_install ")


    # 01 - Information Gathering
    if lazymux.strip() == "1" or lazymux.strip() == "01":
        print("\n    [01] Nmap：网络发现和安全审计工具")
        print("    [02] Red Hawk：信息收集、漏洞扫描和爬网")
        print("    [03] D-TECT：全能渗透测试工具")
        print("    [04] sqlmap：自动SQL注入和数据库接管工具")
        print("    [05] Infoga：收集电子邮件账户信息的工具")
        print("    [06] ReconDog：信息收集和漏洞扫描工具")
        print("    [07] AndroZenmap")
        print("    [08] sqlmate：SQLmap的好伙伴，能完成你一直期望SQLmap做的事")
        print("    [09] AstraNmap：用于查找计算机网络上的主机和服务的安全扫描器")
        print("    [10] MapEye：精确的GPS位置追踪器（支持Android、IOS、Windows手机）")
        print("    [11] Easymap：Nmap快捷方式")
        print("    [12] BlackBox：渗透测试框架")
        print("    [13] XD3v：强大的工具，可以让你了解手机的所有重要信息")
        print("    [14] Crips：这个工具是一系列在线IP工具的集合，可用于快速获取有关IP地址、网页和DNS记录的信息")
        print("    [15] SIR：从网络上解析Skype名字的最后已知IP")
        print("    [16] EvilURL：生成用于IDN同形攻击的Unicode恶意域名并检测它们")
        print("    [17] Striker：侦察与漏洞扫描套件")
        print("    [18] Xshell：工具套件")
        print("    [19] OWScan：OVID Web Scanner")
        print("    [20] OSIF：开源Facebook信息工具")
        print("    [21] Devploit：简单的信息收集工具")
        print("    [22] Namechk：基于namechk.com的Osint工具，用于检查超过100个网站、论坛和社交网络上的用户名")
        print("    [23] AUXILE：Web应用分析框架")
        print("    [24] inther：使用shodan、censys和hackertarget进行信息收集")
        print("    [25] GINF：GitHub信息收集工具")
        print("    [26] GPS追踪")
        print("    [27] ASU：Facebook黑客工具套件")
        print("    [28] fim：Facebook图片下载器")
        print("    [29] MaxSubdoFinder：发现子域的工具")
        print("    [30] pwnedOrNot：用于查找被泄露账户密码的OSINT工具")
        print("    [31] Mac-Lookup：查找特定Mac地址的信息")
        print("    [32] BillCipher：网站或IP地址的信息收集工具")
        print("    [33] dnsrecon：安全评估和网络故障排除")
        print("    [34] zphisher：自动化钓鱼工具")
        print("    [35] Mr.SIP：基于SIP的审计和攻击工具")
        print("    [36] Sherlock：通过用户名追踪社交媒体账户")
        print("    [37] userrecon：在超过75个社交网络上查找用户名")
        print("    [38] PhoneInfoga：使用免费资源扫描电话号码的高级工具之一")
        print("    [39] SiteBroker：一个跨平台的基于Python的信息收集和渗透测试自动化工具")
        print("    [40] maigret：通过用户名从数千个网站收集个人档案")
        print("    [41] GatheTOOL：信息收集 - API hackertarget.com")
        print("    [42] ADB-ToolKit")
        print("    [43] TekDefense-Automater：Automater - IP URL和MD5 OSINT分析")
        print("    [44] EagleEye：通过图像识别和逆向图像搜索找到朋友的Instagram、FB和Twitter资料")
        print("    [45] EyeWitness：旨在为网站截图，提供一些服务器头信息，并在可能的情况下识别默认凭证")
        print("    [46] InSpy：基于Python的LinkedIn枚举工具")
        print("    [47] Leaked：Leaked? 2.1 - 一个检查哈希代码、密码和电子邮件泄露的工具")
        print("    [48] fierce：一个用于定位非连续IP空间的DNS侦察工具")
        print("    [49] gasmask：信息收集工具 - OSINT")
        print("    [50] osi.ig：信息收集（Instagram）")
        print("\n    [00] 返回主菜单\n")
        infogathering = input("lzmx > set_install ")

        if infogathering == "@":
            infogathering = ""
            for x in range(1,201):
                infogathering += f"{x} "
        if len(infogathering.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for infox in infogathering.split():
            if infox.strip() == "01" or infox.strip() == "1": nmap()
            elif infox.strip() == "02" or infox.strip() == "2": red_hawk()
            elif infox.strip() == "03" or infox.strip() == "3": dtect()
            elif infox.strip() == "04" or infox.strip() == "4": sqlmap()
            elif infox.strip() == "05" or infox.strip() == "5": infoga()
            elif infox.strip() == "06" or infox.strip() == "6": reconDog()
            elif infox.strip() == "07" or infox.strip() == "7": androZenmap()
            elif infox.strip() == "08" or infox.strip() == "8": sqlmate()
            elif infox.strip() == "09" or infox.strip() == "9": astraNmap()
            elif infox.strip() == "10": mapeye()
            elif infox.strip() == "11": easyMap()
            elif infox.strip() == "12": blackbox()
            elif infox.strip() == "13": xd3v()
            elif infox.strip() == "14": crips()
            elif infox.strip() == "15": sir()
            elif infox.strip() == "16": evilURL()
            elif infox.strip() == "17": striker()
            elif infox.strip() == "18": xshell()
            elif infox.strip() == "19": owscan()
            elif infox.strip() == "20": osif()
            elif infox.strip() == "21": devploit()
            elif infox.strip() == "22": namechk()
            elif infox.strip() == "23": auxile()
            elif infox.strip() == "24": inther()
            elif infox.strip() == "25": ginf()
            elif infox.strip() == "26": gpstr()
            elif infox.strip() == "27": asu()
            elif infox.strip() == "28": fim()
            elif infox.strip() == "29": maxsubdofinder()
            elif infox.strip() == "30": pwnedOrNot()
            elif infox.strip() == "31": maclook()
            elif infox.strip() == "32": billcypher()
            elif infox.strip() == "33": dnsrecon()
            elif infox.strip() == "34": zphisher()
            elif infox.strip() == "35": mrsip()
            elif infox.strip() == "36": sherlock()
            elif infox.strip() == "37": userrecon()
            elif infox.strip() == "38": phoneinfoga()
            elif infox.strip() == "39": sitebroker()
            elif infox.strip() == "40": maigret()
            elif infox.strip() == "41": gathetool()
            elif infox.strip() == "42": adbtk()
            elif infox.strip() == "43": tekdefense()
            elif infox.strip() == "44": eagleeye()
            elif infox.strip() == "45": eyewitness()
            elif infox.strip() == "46": inspy()
            elif infox.strip() == "47": leaked()
            elif infox.strip() == "48": fierce()
            elif infox.strip() == "49": gasmask()
            elif infox.strip() == "50": osi_ig()
            elif infox.strip() == "00" or infox.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
 
    # 02 - Vulnerability Analysis
    elif lazymux.strip() == "2" or lazymux.strip() == "02":
        print("\n    [01] Nmap：网络发现和安全审计工具")
        print("    [02] AndroZenmap")
        print("    [03] AstraNmap：用于在计算机网络上查找主机和服务的安全扫描器")
        print("    [04] Easymap：Nmap快捷方式")
        print("    [05] Red Hawk：信息收集、漏洞扫描和爬网")
        print("    [06] D-TECT：全能渗透测试工具")
        print("    [07] Damn Small SQLi Scanner：一个完整功能的SQL注入漏洞扫描器（支持GET和POST参数），代码不到100行")
        print("    [08] SQLiv：大规模SQL注入漏洞扫描器")
        print("    [09] sqlmap：自动SQL注入和数据库接管工具")
        print("    [10] sqlscan：快速SQL扫描器、Dorker、PHP Webshell注入器")
        print("    [11] Wordpresscan：用Python重写的WPScan + 一些WPSeku的想法")
        print("    [12] WPScan：免费的WordPress安全扫描器")
        print("    [13] sqlmate：SQLmap的好友，会做你一直期望SQLmap做的事")
        print("    [14] termux-wordpresscan")
        print("    [15] TM-scanner：termux网站漏洞扫描器")
        print("    [16] Rang3r：多线程IP + 端口扫描器")
        print("    [17] Striker：侦察与漏洞扫描套件")
        print("    [18] Routersploit：嵌入式设备的利用框架")
        print("    [19] Xshell：工具套件")
        print("    [20] SH33LL：Shell扫描器")
        print("    [21] BlackBox：渗透测试框架")
        print("    [22] XAttacker：网站漏洞扫描器和自动利用工具")
        print("    [23] OWScan：OVID Web扫描器")
        print("    [24] XPL-SEARCH：在多个漏洞数据库中搜索漏洞")
        print("    [25] AndroBugs_Framework：一个高效的Android漏洞扫描器，帮助开发者或黑客找到Android应用程序中的潜在安全漏洞")
        print("    [26] Clickjacking-Tester：一个Python脚本，设计用于检查网站是否易受点击劫持并创建一个概念验证")
        print("    [27] Sn1per：攻击表面管理平台 | Sn1perSecurity LLC")
        print("\n    [00] 返回主菜单\n")
        vulnsys = input("lzmx > set_install ")
        if vulnsys == "@":
            vulnsys = ""
            for x in range(1,201):
                vulnsys += f"{x} "
        if len(vulnsys.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for vulnx in vulnsys.split():
            if vulnsys.strip() == "01" or vulnsys.strip() == "1": nmap()
            elif vulnsys.strip() == "02" or vulnsys.strip() == "2": androZenmap()
            elif vulnsys.strip() == "03" or vulnsys.strip() == "3": astraNmap()
            elif vulnsys.strip() == "04" or vulnsys.strip() == "4": easyMap()
            elif vulnsys.strip() == "05" or vulnsys.strip() == "5": red_hawk()
            elif vulnsys.strip() == "06" or vulnsys.strip() == "6": dtect()
            elif vulnsys.strip() == "07" or vulnsys.strip() == "7": dsss()
            elif vulnsys.strip() == "08" or vulnsys.strip() == "8": sqliv()
            elif vulnsys.strip() == "09" or vulnsys.strip() == "9": sqlmap()
            elif vulnsys.strip() == "10": sqlscan()
            elif vulnsys.strip() == "11": wordpreSScan()
            elif vulnsys.strip() == "12": wpscan()
            elif vulnsys.strip() == "13": sqlmate()
            elif vulnsys.strip() == "14": wordpresscan()
            elif vulnsys.strip() == "15": tmscanner()
            elif vulnsys.strip() == "16": rang3r()
            elif vulnsys.strip() == "17": striker()
            elif vulnsys.strip() == "18": routersploit()
            elif vulnsys.strip() == "19": xshell()
            elif vulnsys.strip() == "20": sh33ll()
            elif vulnsys.strip() == "21": blackbox()
            elif vulnsys.strip() == "22": xattacker()
            elif vulnsys.strip() == "23": owscan()
            elif vulnsys.strip() == "24": xplsearch()
            elif vulnsys.strip() == "25": androbugs()
            elif vulnsys.strip() == "26": clickjacking()
            elif vulnsys.strip() == "27": sn1per()
            elif vulnsys.strip() == "00" or vulnsys.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)

    # 03 - Web Hacking
    elif lazymux.strip() == "3" or lazymux.strip() == "03":
        print("\n    [01] sqlmap：自动SQL注入和数据库接管工具")
        print("    [02] WebDAV：WebDAV文件上传利用工具")
        print("    [03] MaxSubdoFinder：子域名发现工具")
        print("    [04] Webdav Mass Exploit")
        print("    [05] Atlas：快速SQLMap Tamper建议器")
        print("    [06] sqldump：轻松转储SQL结果的网站")
        print("    [07] Websploit：高级中间人攻击框架")
        print("    [08] sqlmate：SQLmap的好友，将完成您一直期待SQLmap做的事情")
        print("    [09] inther：使用shodan、censys和hackertarget进行信息收集")
        print("    [10] HPB：HTML页面构建器")
        print("    [11] Xshell：工具套件")
        print("    [12] SH33LL：Shell扫描器")
        print("    [13] XAttacker：网站漏洞扫描器和自动利用工具")
        print("    [14] XSStrike：最先进的XSS扫描器")
        print("    [15] Breacher：高级多线程管理面板查找器")
        print("    [16] OWScan：OVID Web扫描器")
        print("    [17] ko-dork：一个简单的漏洞网络扫描器")
        print("    [18] ApSca：强大的网络渗透应用程序")
        print("    [19] amox：通过字典攻击寻找网站上植入的后门或Shell")
        print("    [20] FaDe：使用kindeditor、fckeditor和webdav进行假冒破坏")
        print("    [21] AUXILE：Auxile框架")
        print("    [22] xss-payload-list：跨站脚本（XSS）漏洞载荷列表")
        print("    [23] Xadmin：管理面板查找器")
        print("    [24] CMSeeK：CMS检测和利用套件 - 扫描WordPress、Joomla、Drupal和其他180多种CMS")
        print("    [25] CMSmap：一个开源CMS扫描器，自动化检测最流行CMS的安全缺陷的过程")
        print("    [26] CrawlBox：穷举网页目录的简单方法")
        print("    [27] LFISuite：完全自动的LFI利用器（+反向Shell）和扫描器")
        print("    [28] Parsero：Robots.txt审计工具")
        print("    [29] Sn1per：攻击表面管理平台 | Sn1perSecurity LLC")
        print("    [30] Sublist3r：快速子域名枚举工具，用于渗透测试人员")
        print("    [31] WP-plugin-scanner：一个用于列出安装在WordPress网站上的插件的工具")
        print("    [32] WhatWeb：下一代网络扫描器")
        print("    [33] fuxploider：文件上传漏洞扫描和利用工具")
        print("\n    [00] 返回主菜单\n")

        webhack = input("lzmx > set_install ")
        if webhack == "@":
            webhack = ""
            for x in range(1,201):
                webhack += f"{x} "
        if len(webhack.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for webhx in webhack.split():
            if webhx.strip() == "01" or webhx.strip() == "1": sqlmap()
            elif webhx.strip() == "02" or webhx.strip() == "2": webdav()
            elif webhx.strip() == "03" or webhx.strip() == "3": maxsubdofinder()
            elif webhx.strip() == "04" or webhx.strip() == "4": webmassploit()
            elif webhx.strip() == "05" or webhx.strip() == "5": atlas()
            elif webhx.strip() == "06" or webhx.strip() == "6": sqldump()
            elif webhx.strip() == "07" or webhx.strip() == "7": websploit()
            elif webhx.strip() == "08" or webhx.strip() == "8": sqlmate()
            elif webhx.strip() == "09" or webhx.strip() == "9": inther()
            elif webhx.strip() == "10": hpb()
            elif webhx.strip() == "11": xshell()
            elif webhx.strip() == "12": sh33ll()
            elif webhx.strip() == "13": xattacker()
            elif webhx.strip() == "14": xsstrike()
            elif webhx.strip() == "15": breacher()
            elif webhx.strip() == "16": owscan()
            elif webhx.strip() == "17": kodork()
            elif webhx.strip() == "18": apsca()
            elif webhx.strip() == "19": amox()
            elif webhx.strip() == "20": fade()
            elif webhx.strip() == "21": auxile()
            elif webhx.strip() == "22": xss_payload_list()
            elif webhx.strip() == "23": xadmin()
            elif webhx.strip() == "24": cmseek()
            elif webhx.strip() == "25": cmsmap()
            elif webhx.strip() == "26": crawlbox()
            elif webhx.strip() == "27": lfisuite()
            elif webhx.strip() == "28": parsero()
            elif webhx.strip() == "29": sn1per()
            elif webhx.strip() == "30": sublist3r()
            elif webhx.strip() == "31": wppluginscanner()
            elif webhx.strip() == "32": whatweb()
            elif webhx.strip() == "33": fuxploider()
            elif webhx.strip() == "00" or webhx.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 04 - Database Assessment
    elif lazymux.strip() == "4" or lazymux.strip() == "04":
        print("\n    [01] DbDat：DbDat对数据库进行多项检查以评估安全性")
        print("    [02] sqlmap：自动SQL注入和数据库接管工具")
        print("    [03] NoSQLMap：自动化NoSQL数据库枚举和Web应用利用工具")
        print("    [04] audit_couchdb：检测CouchDB服务器中的安全问题，无论大小")
        print("    [05] mongoaudit：一个自动化的渗透测试工具，用于检查您的MongoDB实例是否得到了适当的保护")
        print("\n    [00] 返回主菜单\n")

        dbssm = input("lzmx > set_install ")
        if dbssm == "@":
            dbssm = ""
            for x in range(1,201):
                dbssm += f"{x} "
        if len(dbssm.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for dbsx in dbssm.split():
            if dbsx.strip() == "01" or dbsx.strip() == "1": dbdat()
            elif dbsx.strip() == "02" or dbsx.strip() == "2": sqlmap()
            elif dbsx.strip() == "03" or dbsx.strip() == "3": nosqlmap
            elif dbsx.strip() == "04" or dbsx.strip() == "4": audit_couchdb()
            elif dbsx.strip() == "05" or dbsx.strip() == "5": mongoaudit()
            elif dbsx.strip() == "00" or dbsx.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 05 - Password Attacks
    elif lazymux.strip() == "5" or lazymux.strip() == "05":
        print("\n    [01] Hydra：支持多种服务的网络登录破解工具")
        print("    [02] FMBrute：Facebook多重暴力破解")
        print("    [03] HashID：用于识别不同类型哈希的软件")
        print("    [04] Facebook Brute Force 3")
        print("    [05] Black Hydra：一个简化Hydra暴力破解会话的小程序")
        print("    [06] Hash Buster：几秒钟内破解哈希")
        print("    [07] FBBrute：Facebook暴力破解")
        print("    [08] Cupp：常用用户密码剖析器")
        print("    [09] InstaHack：Instagram暴力破解")
        print("    [10] 印度尼西亚词表")
        print("    [11] Xshell")
        print("    [12] Aircrack-ng：WiFi安全审计工具套件")
        print("    [13] BlackBox：渗透测试框架")
        print("    [14] Katak：一个开源的软件登录暴力破解工具包和哈希解密器")
        print("    [15] Hasher：带自动检测哈希的哈希破解器")
        print("    [16] Hash-Generator：美观的哈希生成器")
        print("    [17] nk26：Nkosec编码")
        print("    [18] Hasherdotid：一个用于查找加密文本的工具")
        print("    [19] Crunch：高度可定制的词表生成器")
        print("    [20] Hashcat：世界上最快最先进的密码恢复工具")
        print("    [21] ASU：Facebook黑客工具包")
        print("    [22] Credmap：一个开源工具，旨在提高对凭证重用危险的意识")
        print("    [23] BruteX：自动对目标上运行的所有服务进行暴力破解")
        print("    [24] Gemail-Hack：一个用于通过暴力破解方法入侵Gmail账户的Python脚本")
        print("    [25] GoblinWordGenerator：Python词表生成器")
        print("    [26] PyBozoCrack：一个简单而有效的Python MD5破解器")
        print("    [27] brutespray：从Nmap输出暴力破解 - 自动尝试发现服务的默认凭证")
        print("    [28] crowbar：可在渗透测试中使用的暴力破解工具")
        print("    [29] elpscrk：基于用户画像、排列组合和统计的智能词表生成器")
        print("    [30] fbht：Facebook黑客工具")
        print("\n    [00] 返回主菜单\n")

        passtak = input("lzmx > set_install ")
        if passtak == "@":
            passtak = ""
            for x in range(1,201):
                passtak += f"{x} "
        if len(passtak.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for passx in passtak.split():
            if passx.strip() == "01" or passx.strip() == "1": hydra()
            elif passx.strip() == "02" or passx.strip() == "2": fmbrute()
            elif passx.strip() == "03" or passx.strip() == "3": hashid()
            elif passx.strip() == "04" or passx.strip() == "4": fbBrute()
            elif passx.strip() == "05" or passx.strip() == "5": black_hydra()
            elif passx.strip() == "06" or passx.strip() == "6": hash_buster()
            elif passx.strip() == "07" or passx.strip() == "7": fbbrutex()
            elif passx.strip() == "08" or passx.strip() == "8": cupp()
            elif passx.strip() == "09" or passx.strip() == "9": instaHack()
            elif passx.strip() == "10": indonesian_wordlist()
            elif passx.strip() == "11": xshell()
            elif passx.strip() == "12": aircrackng()
            elif passx.strip() == "13": blackbox()
            elif passx.strip() == "14": katak()
            elif passx.strip() == "15": hasher()
            elif passx.strip() == "16": hashgenerator()
            elif passx.strip() == "17": nk26()
            elif passx.strip() == "18": hasherdotid()
            elif passx.strip() == "19": crunch()
            elif passx.strip() == "20": hashcat()
            elif passx.strip() == "21": asu()
            elif passx.strip() == "22": credmap()
            elif passx.strip() == "23": brutex()
            elif passx.strip() == "24": gemailhack()
            elif passx.strip() == "25": goblinwordgenerator()
            elif passx.strip() == "26": pybozocrack()
            elif passx.strip() == "27": brutespray()
            elif passx.strip() == "28": crowbar()
            elif passx.strip() == "29": elpscrk()
            elif passx.strip() == "30": fbht()
            elif passx.strip() == "00" or passx.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 06 - Wireless Attacks
    elif lazymux.strip() == "6" or lazymux.strip() == "06":
        print("\n    [01] Aircrack-ng：WiFi安全审计工具套件")
        print("    [02] Wifite：自动化无线攻击工具")
        print("    [03] Wifiphisher：流氓接入点框架")
        print("    [04] Routersploit：嵌入式设备的利用框架")
        print("    [05] PwnSTAR：（Pwn SofT-Ap scRipt）- 满足您所有假AP需求的工具！")
        print("    [06] Pyrit：著名的WPA预计算破解器，从Google迁移而来")
        print("\n    [00] 返回主菜单\n")

        wiretak = input("lzmx > set_install ")
        if wiretak == "@":
            wiretak = ""
            for x in range(1,201):
                wiretak += f"{x} "
        if len(wiretak.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for wirex in wiretak.split():
            if wirex.strip() == "01" or wirex.strip() == "1": aircrackng()
            elif wirex.strip() == "02" or wirex.strip() == "2": wifite()
            elif wirex.strip() == "03" or wirex.strip() == "3": wifiphisher()
            elif wirex.strip() == "04" or wirex.strip() == "4": routersploit()
            elif wirex.strip() == "05" or wirex.strip() == "5": pwnstar()
            elif wirex.strip() == "06" or wirex.strip() == "6": pyrit()
            elif wirex.strip() == "00" or wirex.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 07 - Reverse Engineering
    elif lazymux.strip() == "7" or lazymux.strip() == "07":
        print("\n    [01] 二进制利用")
        print("    [02] jadx：DEX到JAVA反编译器")
        print("    [03] apktool：用于逆向工程Android应用程序的工具")
        print("    [04] uncompyle6：Python跨版本字节码反编译器")
        print("    [05] ddcrypt：DroidScript APK去混淆工具")
        print("    [06] CFR：又一个Java反编译器")
        print("    [07] UPX：最终的可执行文件打包器")
        print("    [08] pyinstxtractor：PyInstaller提取器")
        print("    [09] innoextract：一个用来解包由Inno Setup创建的安装程序的工具")
        print("    [10] pycdc：C++ Python字节码反汇编器和反编译器")
        print("    [11] APKiD：Android应用程序的标识器，用于包装器、保护器、混淆器和奇异性 - Android的PEiD")
        print("    [12] DTL-X：Python APK反编译和修补工具")
        print("    [13] APKLeaks：扫描APK文件寻找URIs、端点和秘密")
        print("    [14] apk-mitm：一个自动准备Android APK文件以进行HTTPS检查的CLI应用程序")
        print("    [15] ssl-pinning-remover：Android应用程序的SSL Pinning移除器")
        print("    [16] GEF：GEF（GDB增强功能）- 一个为GDB提供现代体验的工具，具有高级调试能力，适用于Linux上的漏洞开发者和逆向工程师")
        print("\n    [00] 返回主菜单\n")

        reversi = input("lzmx > set_install ")
        if reversi == "@":
            reversi = ""
            for x in range(1,201):
                reversi += f"{x} "
        if len(reversi.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for revex in reversi.split():
            if revex.strip() == "01" or revex.strip() == "1": binploit()
            elif revex.strip() == "02" or revex.strip() == "2": jadx()
            elif revex.strip() == "03" or revex.strip() == "3": apktool()
            elif revex.strip() == "04" or revex.strip() == "4": uncompyle()
            elif revex.strip() == "05" or revex.strip() == "5": ddcrypt()
            elif revex.strip() == "06" or revex.strip() == "6": cfr()
            elif revex.strip() == "07" or revex.strip() == "7": upx()
            elif revex.strip() == "08" or revex.strip() == "8": pyinstxtractor()
            elif revex.strip() == "09" or revex.strip() == "9": innoextract()
            elif revex.strip() == "10": pycdc()
            elif revex.strip() == "11": apkid()
            elif revex.strip() == "12": dtlx()
            elif revex.strip() == "13": apkleaks()
            elif revex.strip() == "14": apkmitm()
            elif revex.strip() == "15": ssl_pinning_remover()
            elif revex.strip() == "16": gef()
            elif revex.strip() == "00" or revex.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 08 - Exploitation Tools
    elif lazymux.strip() == "8" or lazymux.strip() == "08":
        print("\n    [01] Metasploit：高级开源平台，用于开发、测试和使用漏洞利用代码")
        print("    [02] commix：自动化的全能OS命令注入和利用工具")
        print("    [03] BlackBox：渗透测试框架")
        print("    [04] Brutal：类似于rubber ducky的Payload，但语法不同")
        print("    [05] TXTool：易用的渗透测试工具")
        print("    [06] XAttacker：网站漏洞扫描器和自动利用工具")
        print("    [07] Websploit：高级中间人攻击框架")
        print("    [08] Routersploit：嵌入式设备的利用框架")
        print("    [09] A-Rat：远程管理工具")
        print("    [10] BAF：盲目攻击框架")
        print("    [11] Gloom-Framework：Linux渗透测试框架")
        print("    [12] Zerodoor：一个懒散编写的脚本，用于随时生成跨平台后门 :)")
        print("\n    [00] 返回主菜单\n")

        exploitool = input("lzmx > set_install ")
        if exploitool == "@":
            exploitool = ""
            for x in range(1,201):
                exploitool += f"{x} "
        if len(exploitool.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for explx in exploitool.split():
            if explx.strip() == "01" or explx.strip() == "1": metasploit()
            elif explx.strip() == "02" or explx.strip() == "2": commix()
            elif explx.strip() == "03" or explx.strip() == "3": blackbox()
            elif explx.strip() == "04" or explx.strip() == "4": brutal()
            elif explx.strip() == "05" or explx.strip() == "5": txtool()
            elif explx.strip() == "06" or explx.strip() == "6": xattacker()
            elif explx.strip() == "07" or explx.strip() == "7": websploit()
            elif explx.strip() == "08" or explx.strip() == "8": routersploit()
            elif explx.strip() == "09" or explx.strip() == "9": arat()
            elif explx.strip() == "10": baf()
            elif explx.strip() == "11": gloomframework()
            elif explx.strip() == "12": zerodoor()
            elif explx.strip() == "00" or explx.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 09 - Sniffing and Spoofing
    elif lazymux.strip() == "9" or lazymux.strip() == "09":
        print("\n    [01] KnockMail：验证电子邮件是否存在")
        print("    [02] tcpdump：功能强大的命令行数据包分析器")
        print("    [03] Ettercap：全面的中间人攻击套件，可以实时嗅探连接、即时进行内容过滤等等")
        print("    [04] hping3：hping是一个面向命令行的TCP/IP数据包组装/分析工具")
        print("    [05] tshark：网络协议分析器和嗅探器")
        print("\n    [00] 返回主菜单\n")

        sspoof = input("lzmx > set_install ")
        if sspoof == "@":
            sspoof = ""
            for x in range(1,201):
                sspoof += f"{x} "
        if len(sspoof.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for sspx in sspoof.split():
            if sspx.strip() == "01" or sspx.strip() == "1": knockmail()
            elif sspx.strip() == "02" or sspx.strip() == "2": tcpdump()
            elif sspx.strip() == "03" or sspx.strip() == "3": ettercap()
            elif sspx.strip() == "04" or sspx.strip() == "4": hping3()
            elif sspx.strip() == "05" or sspx.strip() == "5": tshark()
            elif sspx.strip() == "00" or sspx.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 10 - Reporting Tools
    elif lazymux.strip() == "10":
        print("\n    [01] dos2unix：转换DOS和Unix文本文件")
        print("    [02] exiftool：用于读取、写入和编辑多种文件中的元信息的工具")
        print("    [03] iconv：在不同字符编码之间转换的工具")
        print("    [04] mediainfo：用于从媒体文件读取信息的命令行工具")
        print("    [05] pdfinfo：PDF文档信息提取器")
        print("\n    [00] 返回主菜单\n")

        reportls = input("lzmx > set_install ")
        if reportls == "@":
            reportls = ""
            for x in range(1,201):
                reportls += f"{x} "
        if len(reportls.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for reportx in reportls.split():
            if reportx.strip() == "01" or reportx.strip() == "1": dos2unix()
            elif reportx.strip() == "02" or reportx.strip() == "2": exiftool()
            elif reportx.strip() == "03" or reportx.strip() == "3": iconv()
            elif reportx.strip() == "04" or reportx.strip() == "4": mediainfo()
            elif reportx.strip() == "05" or reportx.strip() == "5": pdfinfo()
            elif reportx.strip() == "00" or reportx.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 11 - Forensic Tools
    elif lazymux.strip() == "11":
        print("\n    [01] steghide：通过替换一些最不重要的位来在文件中嵌入消息")
        print("    [02] tesseract：Tesseract 可能是目前最准确的开源 OCR 引擎")
        print("    [03] sleuthkit：The Sleuth Kit (TSK) 是一个数字取证工具的库")
        print("    [04] CyberScan：网络取证工具包")
        print("    [05] binwalk：固件分析工具")
        print("\n    [00] 返回主菜单\n")

        forensc = input("lzmx > set_install ")
        if forensc == "@":
            forensc = ""
            for x in range(1,201):
                forensc += f"{x} "
        if len(forensc.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for forenx in forensc.split():
            if forenx.strip() == "01" or forenx.strip() == "1": steghide()
            elif forenx.strip() == "02" or forenx.strip() == "2": tesseract()
            elif forenx.strip() == "03" or forenx.strip() == "3": sleuthkit()
            elif forenx.strip() == "04" or forenx.strip() == "4": cyberscan()
            elif forenx.strip() == "05" or forenx.strip() == "5": binwalk()
            elif forenx.strip() == "00" or forenx.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 12 - Stress Testing
    elif lazymux.strip() == "12":
        print("\n    [01] Torshammer：慢速POST DDOS工具")
        print("    [02] Slowloris：低带宽DoS工具")
        print("    [03] Fl00d & Fl00d2：UDP洪水攻击工具")
        print("    [04] GoldenEye：GoldenEye第7层（KeepAlive+NoCache）DoS测试工具")
        print("    [05] Xerxes：最强大的DoS工具")
        print("    [06] Planetwork-DDOS")
        print("    [07] Xshell")
        print("    [08] santet-online：社会工程学工具")
        print("    [09] dost-attack：Web服务器攻击工具")
        print("    [10] DHCPig：使用scapy网络库用Python编写的DHCP枯竭脚本")
        print("\n    [00] 返回主菜单\n")

        stresstest = input("lzmx > set_install ")
        if stresstest == "@":
            stresstest = ""
            for x in range(1,201):
                stresstest += f"{x} "
        if len(stresstest.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for stressx in stresstest.split():
            if stressx.strip() == "01" or stressx.strip() == "1": torshammer()
            elif stressx.strip() == "02" or stressx.strip() == "2": slowloris()
            elif stressx.strip() == "03" or stressx.strip() == "3": fl00d12()
            elif stressx.strip() == "04" or stressx.strip() == "4": goldeneye()
            elif stressx.strip() == "05" or stressx.strip() == "5": xerxes()
            elif stressx.strip() == "06" or stressx.strip() == "6": planetwork_ddos()
            elif stressx.strip() == "07" or stressx.strip() == "7": xshell()
            elif stressx.strip() == "08" or stressx.strip() == "8": sanlen()
            elif stressx.strip() == "09" or stressx.strip() == "9": dostattack()
            elif stressx.strip() == "10": dhcpig()
            elif stressx.strip() == "00" or stressx.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 13 - Install Linux Distro
    elif lazymux.strip() == "13":
        print("\n    [01] Ubuntu (impish)")
        print("    [02] Fedora")
        print("    [03] Kali Nethunter")
        print("    [04] Parrot")
        print("    [05] Arch Linux")
        print("    [06] Alpine Linux (edge)")
        print("    [07] Debian (bullseye)")
        print("    [08] Manjaro AArch64")
        print("    [09] OpenSUSE (Tumbleweed)")
        print("    [10] Void Linux")
        print("\n    [00] 返回主菜单\n")

        innudis = input("lzmx > set_install ")
        if innudis == "@":
            innudis = ""
            for x in range(1,201):
                innudis += f"{x} "
        if len(innudis.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for innux in innudis.split():
            if innux.strip() == "01" or innux.strip() == "1": ubuntu()
            elif innux.strip() == "02" or innux.strip() == "2": fedora()
            elif innux.strip() == "03" or innux.strip() == "3": nethunter()
            elif innux.strip() == "04" or innux.strip() == "4": parrot()
            elif innux.strip() == "05" or innux.strip() == "5": archlinux()
            elif innux.strip() == "06" or innux.strip() == "6": alpine()
            elif innux.strip() == "07" or innux.strip() == "7": debian()
            elif innux.strip() == "08" or innux.strip() == "8": manjaroArm64()
            elif innux.strip() == "09" or innux.strip() == "9": opensuse()
            elif innux.strip() == "10": voidLinux()
            elif innux.strip() == "00" or innux.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 14 - Termux Utility
    elif lazymux.strip() == "14":
        print("\n    [01] SpiderBot: 使用随机代理和用户代理来访问网站")
        print("    [02] Ngrok: 将本地端口隧道转发到公共 URL 并检查流量")
        print("    [03] Sudo: Android 上的 sudo 安装程序")
        print("    [04] google: Python 对 Google 搜索引擎的绑定")
        print("    [05] kojawafft")
        print("    [06] ccgen: 信用卡生成器")
        print("    [07] VCRT: 病毒创建器")
        print("    [08] E-Code: PHP 脚本编码器")
        print("    [09] Termux-Styling")
        print("    [11] xl-py: XL 直购包")
        print("    [12] BeanShell: 一个小型、免费的、可嵌入的 Java 源代码解释器，具有对象脚本语言功能，用 Java 编写")
        print("    [13] vbug: 病毒制造器")
        print("    [14] Crunch: 高度可定制的单词列表生成器")
        print("    [15] Textr: 运行文本的简单工具")
        print("    [16] heroku: 与 Heroku 交互的命令行界面")
        print("    [17] RShell: 单个监听的反向 shell")
        print("    [18] TermPyter: 修复在 termux 上安装 Jupyter 时的所有错误")
        print("    [19] Numpy: Python 科学计算的基本包")
        print("    [20] BTC-to-IDR-checker: 从 Bitcoin.co.id API 检查虚拟货币到印尼卢比的汇率")
        print("    [21] ClickBot: 使用 Telegram 机器人赚钱")
        print("    [22] pandas: 强大的开源数据处理和分析库")
        print("    [23] jupyter-notebook: 交互式网络应用程序，允许用户创建和分享包含实时代码、方程式、可视化和叙述文本的文档")
        print("\n    [00] 返回主菜单\n")

        moretool = input("lzmx > set_install ")
        if moretool == "@":
            moretool = ""
            for x in range(1,201):
                moretool += f"{x} "
        if len(moretool.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for moret in moretool.split():
            if moret.strip() == "01" or moret.strip() == "1": spiderbot()
            elif moret.strip() == "02" or moret.strip() == "2": ngrok()
            elif moret.strip() == "03" or moret.strip() == "3": sudo()
            elif moret.strip() == "04" or moret.strip() == "4": google()
            elif moret.strip() == "05" or moret.strip() == "5": kojawafft()
            elif moret.strip() == "06" or moret.strip() == "6": ccgen()
            elif moret.strip() == "07" or moret.strip() == "7": vcrt()
            elif moret.strip() == "08" or moret.strip() == "8": ecode()
            elif moret.strip() == "09" or moret.strip() == "9": stylemux()
            elif moret.strip() == "10": passgencvar()
            elif moret.strip() == "11": xlPy()
            elif moret.strip() == "12": beanshell()
            elif moret.strip() == "13": vbug()
            elif moret.strip() == "14": crunch()
            elif moret.strip() == "15": textr()
            elif moret.strip() == "16": heroku()
            elif moret.strip() == "17": rshell()
            elif moret.strip() == "18": termpyter()
            elif moret.strip() == "19": numpy()
            elif moret.strip() == "20": btc2idr()
            elif moret.strip() == "21": clickbot()
            elif moret.strip() == "22": pandas()
            elif moret.strip() == "23": notebook()
            elif moret.strip() == "00" or moret.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 15 - Shell Function [.bashrc]
    elif lazymux.strip() == "15":
        print("\n    [01] FBVid（FB 视频下载器）")
        print("    [02] cast2video（Asciinema Cast 转换器）")
        print("    [03] iconset（AIDE 应用图标）")
        print("    [04] readme（GitHub README.md 文件）")
        print("    [05] makedeb（DEB 软件包构建工具）")
        print("    [06] quikfind（文件搜索工具）")
        print("    [07] pranayama（4-7-8 放松呼吸）")
        print("    [08] sqlc（SQLite 查询处理器）")
        print("\n    [00] 返回主菜单\n")

        myshf = input("lzmx > set_install ")
        if myshf == "@":
            myshf = ""
            for x in range(1,201):
                myshf += f"{x} "
        if len(myshf.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for mysh in myshf.split():
            if mysh.strip() == "01" or mysh.strip() == "1": fbvid()
            elif mysh.strip() == "02" or mysh.strip() == "2": cast2video()
            elif mysh.strip() == "03" or mysh.strip() == "3": iconset()
            elif mysh.strip() == "04" or mysh.strip() == "4": readme()
            elif mysh.strip() == "05" or mysh.strip() == "5": makedeb()
            elif mysh.strip() == "06" or mysh.strip() == "6": quikfind()
            elif mysh.strip() == "07" or mysh.strip() == "7": pranayama()
            elif mysh.strip() == "08" or mysh.strip() == "8": sqlc()
            elif mysh.strip() == "00" or mysh.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 16 - Install CLI Games
    elif lazymux.strip() == "16":
        print("\n    [01] Flappy Bird")
        print("    [02] Street Car")
        print("    [03] Speed Typing")
        print("    [04] NSnake: 带文本界面的经典贪吃蛇游戏")
        print("    [05] Moon buggy: 在月球表面驾驶汽车的简单游戏")
        print("    [06] Nudoku: 基于 ncurses 的数独游戏")
        print("    [07] tty-solitaire")
        print("    [08] Pacman4Console")
        print("\n    [00] 返回主菜单\n")

        cligam = input("lzmx > set_install ")
        if cligam == "@":
            cligam = ""
            for x in range(1,201):
                cligam += f"{x} "
        if len(cligam.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for clig in cligam.split():
            if clig.strip() == "01" or clig.strip() == "1": flappy_bird()
            elif clig.strip() == "02" or clig.strip() == "2": street_car()
            elif clig.strip() == "03" or clig.strip() == "3": speed_typing()
            elif clig.strip() == "04" or clig.strip() == "4": nsnake()
            elif clig.strip() == "05" or clig.strip() == "5": moon_buggy()
            elif clig.strip() == "06" or clig.strip() == "6": nudoku()
            elif clig.strip() == "07" or clig.strip() == "7": ttysolitaire()
            elif clig.strip() == "08" or clig.strip() == "8": pacman4console()
            elif clig.strip() == "00" or clig.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 17 - Malware Analysis
    elif lazymux.strip() == "17":
        print("\n    [01] Lynis: 安全审计和 Rootkit 扫描器")
        print("    [02] Chkrootkit: Linux Rootkit 扫描器")
        print("    [03] ClamAV: 杀毒软件工具包")
        print("    [04] Yara: 旨在帮助恶意软件研究人员识别和分类恶意软件样本的工具")
        print("    [05] VirusTotal-CLI: VirusTotal 的命令行界面")
        print("    [06] avpass: 泄露和绕过 Android 恶意软件检测系统的工具")
        print("    [07] DKMC: Dont kill my cat - 恶意负载规避工具")
        print("\n    [00] 返回主菜单\n")

        malsys = input("lzmx > set_install ")
        if malsys == "@":
            malsys = ""
            for x in range(1,201):
                malsys += f"{x} "
        if len(malsys.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for malx in malsys.split():
            if malx.strip() == "01" or malx.strip() == "1": lynis()
            elif malx.strip() == "02" or malx.strip() == "2": chkrootkit()
            elif malx.strip() == "03" or malx.strip() == "3": clamav()
            elif malx.strip() == "04" or malx.strip() == "4": yara()
            elif malx.strip() == "05" or malx.strip() == "5": virustotal()
            elif malx.strip() == "06" or malx.strip() == "6": avpass()
            elif malx.strip() == "07" or malx.strip() == "7": dkmc()
            elif malx.strip() == "00" or malx.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 18 - Compiler/Interpreter
    elif lazymux.strip() == "18":
        print("\n    [01] Python2: Python 2 编程语言，旨在编写清晰的程序")
        print("    [02] ecj: Eclipse Java 编译器")
        print("    [03] Golang: Go 编程语言编译器")
        print("    [04] ldc: 使用 LLVM 构建的 D 编程语言编译器")
        print("    [05] Nim: Nim 编程语言编译器")
        print("    [06] shc: Shell 脚本编译器")
        print("    [07] TCC: Tiny C 编译器")
        print("    [08] PHP: 服务器端、HTML 嵌入式脚本语言")
        print("    [09] Ruby: 动态编程语言，注重简单和高效率")
        print("    [10] Perl: 功能丰富的编程语言")
        print("    [11] Vlang: 简单、快速、安全的编译语言，用于开发易于维护的软件")
        print("    [12] BeanShell: 小型、免费、可嵌入的 Java 源代码解释器，具有基于对象的脚本语言功能，用 Java 编写")
        print("    [13] fp-compiler: Free Pascal 是一款专业的 32 位、64 位和 16 位 Pascal 编译器")
        print("    [14] Octave: 科学编程语言")
        print("    [15] BlogC: 博客编译器")
        print("    [16] Dart: 通用编程语言")
        print("    [17] Yasm: 支持 x86 和 AMD64 指令集的汇编器")
        print("    [18] Nasm: 一种具有 Intel 风格语法的跨平台 x86 汇编器")
        print("\n    [00] 返回主菜单\n")

        compter = input("lzmx > set_install ")
        if compter == "@":
            compter = ""
            for x in range(1,201):
                compter += f"{x} "
        if len(compter.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for compt in compter.split():
            if compt.strip() == "01" or compt.strip() == "1": python2()
            elif compt.strip() == "02" or compt.strip() == "2": ecj()
            elif compt.strip() == "03" or compt.strip() == "3": golang()
            elif compt.strip() == "04" or compt.strip() == "4": ldc()
            elif compt.strip() == "05" or compt.strip() == "5": nim()
            elif compt.strip() == "06" or compt.strip() == "6": shc()
            elif compt.strip() == "07" or compt.strip() == "7": tcc()
            elif compt.strip() == "08" or compt.strip() == "8": php()
            elif compt.strip() == "09" or compt.strip() == "9": ruby()
            elif compt.strip() == "10": perl()
            elif compt.strip() == "11": vlang()
            elif compt.strip() == "12": beanshell()
            elif compt.strip() == "13": fpcompiler()
            elif compt.strip() == "14": octave()
            elif compt.strip() == "15": blogc()
            elif compt.strip() == "16": dart()
            elif compt.strip() == "17": yasm()
            elif compt.strip() == "18": nasm()
            elif compt.strip() == "00" or compt.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    
    # 19 - Social Engineering Tools
    elif lazymux.strip() == "19":
        print("\n    [01] weeman: 用 Python 实现的用于钓鱼的 HTTP 服务器")
        print("    [02] SocialFish: 教育用钓鱼工具和信息收集器")
        print("    [03] santet-online: 社会工程学工具")
        print("    [04] SpazSMS: 在同一电话号码上重复发送未经请求的消息")
        print("    [05] LiteOTP: 多重垃圾短信 OTP")
        print("    [06] F4K3: 伪造用户数据生成器")
        print("    [07] Hac")
        print("    [08] Cookie-stealer: 糟糕的 Cookie 窃取者")
        print("    [09] zphisher: 自动化的钓鱼工具")
        print("    [10] Evilginx: 具有两因素身份验证绕过功能的高级钓鱼工具")
        print("    [11] ghost-phisher: 自动从 code.google.com/p/ghost-phisher 导出")
        print("\n    [00] 返回主菜单\n")

        soceng = input("lzmx > set_install ")
        if soceng == "@":
            soceng = ""
            for x in range(1,201):
                soceng += f"{x} "
        if len(soceng.split()) > 1:
            writeStatus(1)
        else:
            writeStatus(0)
        for socng in soceng.split():
            if socng.strip() == "01" or socng.strip() == "1": weeman()
            elif socng.strip() == "02" or socng.strip() == "2": socfish()
            elif socng.strip() == "03" or socng.strip() == "3": sanlen()
            elif socng.strip() == "04" or socng.strip() == "4": spazsms()
            elif socng.strip() == "05" or socng.strip() == "5": liteotp()
            elif socng.strip() == "06" or socng.strip() == "6": f4k3()
            elif socng.strip() == "07" or socng.strip() == "7": hac()
            elif socng.strip() == "08" or socng.strip() == "8": cookiestealer()
            elif socng.strip() == "09" or socng.strip() == "9": zphisher()
            elif socng.strip() == "10": evilginx()
            elif socng.strip() == "11": ghostphisher()
            elif socng.strip() == "00" or socng.strip() == "0": restart_program()
            else: print("\nERROR: Wrong Input");timeout(1);restart_program()
        if readStatus():
            writeStatus(0)
    elif lazymux.strip() == "99":
        os.system("git pull")
    elif lazymux.strip() == "0" or lazymux.strip() == "00":
        sys.exit()
    
    else:
        print("\nERROR: Wrong Input")
        timeout(1)
        restart_program()

if __name__ == "__main__":
    os.system("clear")
    main()