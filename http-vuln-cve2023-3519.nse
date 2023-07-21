-- Usage: nmap --script cve-2023-3519-checker <target>
-- Nmap NSE script for CVE-2023-3519 Citrix unauthenticated remote code execution  
-- Inspried from https://github.com/telekom-security/cve-2023-3519-citrix-scanner


description = [[
Checks target for CVE-2023-3519 vulnerability.
]]

author = "Dhiraj Mishra (@RandomDhiraj)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "vuln"}

references = {
  'https://nvd.nist.gov/vuln/detail/CVE-2023-3519', 
  'https://twitter.com/DTCERT/status/1682032701430452233'
}

description = [[
Checks target for CVE-2023-3519 vulnerability.
Compares "Last-Modified" header in the server response to known patched versions.
]]

categories = {"safe", "vuln"}

local http = require "http"
local shortport = require "shortport"
local strbuf = require "strbuf"

portrule = shortport.ssl

local PATCHED_VERSIONS = {
    "Fri, 07 Jul 2023 15:39:40 GMT",
    "Mon, 10 Jul 2023 17:41:17 GMT",
    "Mon, 10 Jul 2023 18:36:14 GMT"
}

function checkversion(last_modified)
    for _, patch in ipairs(PATCHED_VERSIONS) do
        if last_modified == patch then
            return "Patched version detected"
        end
    end
    return "Potentially vulnerable (Older than 01 Jul 2023)"
end

action = function(host, port)
    local response
    local patched = "Not verifiable"
    local last_modified

    response = http.get(host, port, "/")

    if response.status == 200 then
        last_modified = response.header["last-modified"]
        
        if last_modified then
            patched = checkversion(last_modified)
        else
            last_modified = "N/A"
        end

        return ("IP: %s | Last Modified Header: %s | Result: %s\n"):format(host.ip, last_modified, patched)
    else
        return ("IP: %s | Unable to retrieve response\n"):format(host.ip)
    end
end
