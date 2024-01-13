local http = require "http"
local stdnse = require "stdnse"
local shortport = require "shortport"
local string = require "string"
local vulns = require "vulns"

description = [[
This NSE script checks Ivanti Pulse Secure SSL VPN CVE-2023-46805 & CVE-2024-21887.
]]
---
-- @usage
-- nmap --script http-vuln-cve2023-46805_2024_21887 -p <port> <host>
-- nmap --script http-vuln-cve2023-46805_2024_21887 -p <port> <host> --script-args http.host=<host>
--
-- @output
-- PORT   STATE SERVICE
-- 443/tcp open  http
-- | http-vuln-cve2023-46805_2024_21887: 
-- |   Host is vulnerable to CVE-2023-46805 & CVE-2024-21887 "PulsePitfall".
--

author = "Dhiraj Mishra (@RandomDhiraj)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln"}

portrule = shortport.portnumber(443)

action = function(host, port)
  local vuln = {
    title = 'Pulse Secure Connect "PulsePitfall" CVE-2023-46805 & CVE-2024-21887',
    state = vulns.STATE.NOT_VULN,
    description = [[
      The host retruns with an empty "403" response likely to be vulnerable with CVE-2023-46805 and CVE-2024-21887 Command Injection and Authentication Bypass in Ivanti Connect Secure and Ivanti Policy Secure.
    ]],
    references = {
      'https://labs.watchtowr.com/welcome-to-2024-the-sslvpn-chaos-continues-ivanti-cve-2023-46805-cve-2024-21887/',
      'https://nvd.nist.gov/vuln/detail/CVE-2023-46805',
      'https://nvd.nist.gov/vuln/detail/CVE-2024-21887',
    },
  }
 local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)

  local response = http.get(host, port, "/api/v1/configuration/users/user-roles/user-role/rest-userrole1/web/web-bookmarks/bookmark")
  if response.status == 403 and string.len(response.body) == 0 then
    stdnse.print_debug("%s: %s GET - 403 Forbidden without content - potentially vulnerable", SCRIPT_NAME, host.targetname or host.ip)
    vuln.state = vulns.STATE.VULN
  else
    stdnse.print_debug("%s: The host does not appear to be vulnerable.", SCRIPT_NAME)
  end

  return vuln_report:make_output(vuln)
end
