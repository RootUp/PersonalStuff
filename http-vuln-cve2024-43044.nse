local http = require "http"
local shortport = require "shortport"
local string = require "string"
local vulns = require "vulns"
local nmap = require "nmap"

description = [[
Detects if a Jenkins instance is potentially vulnerable to CVE-2024-43044, 
an arbitrary file read vulnerability that allows an agent to read files from the controller.

References:
* https://www.jenkins.io/security/advisory/2024-03-27/
* https://github.com/convisolabs/CVE-2024-43044-jenkins
]]

---
-- @usage
-- nmap -p <port> --script jenkins-cve-2024-43044-detector <target>
--
-- @output
-- PORT     STATE SERVICE
-- 8080/tcp open  http-proxy
-- | jenkins-cve-2024-43044-detector:
-- |   VULNERABLE:
-- |   Jenkins Arbitrary File Read Vulnerability (CVE-2024-43044)
-- |     State: LIKELY VULNERABLE
-- |     Description:
-- |       Jenkins versions before 2.440, LTS 2.426.3 are potentially vulnerable to 
-- |       CVE-2024-43044, which allows arbitrary file read from the controller.
-- |     Disclosure date: 2024-03-27
-- |     References:
-- |_      https://www.jenkins.io/security/advisory/2024-03-27/

author = "Dhiraj Mishra (@RandomDhiraj)" -- NMAP Script
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

local function get_jenkins_version(host, port)
    local response = http.get(host, port, "/")
    if response.status == 200 then
        local version = response.header["x-jenkins"] or ""
        return version
    end
    return nil
end

local function is_vulnerable(version)
    if not version then return false end
    
    local major, minor, patch = version:match("(%d+)%.(%d+)%.?(%d*)")
    major, minor, patch = tonumber(major), tonumber(minor), tonumber(patch)
    
    if not major or not minor then return false end
    
    if major < 2 then return true end
    if major == 2 and minor < 440 then return true end
    if major == 2 and minor == 426 and (not patch or patch < 3) then return true end
    
    return false
end

action = function(host, port)
    local vuln_table = {
        title = "Jenkins Arbitrary File Read Vulnerability (CVE-2024-43044)",
        state = vulns.STATE.NOT_VULN,
        description = [[
Jenkins versions before 2.440, LTS 2.426.3 are potentially vulnerable to 
CVE-2024-43044, which allows arbitrary file read from the controller.]],
        references = {
            'https://www.jenkins.io/security/advisory/2024-03-27/',
            'https://github.com/convisolabs/CVE-2024-43044-jenkins',
            'https://blog.convisoappsec.com/en/analysis-of-cve-2024-43044/'
        },
        dates = {
            disclosure = {year = 2024, month = 03, day = 27},
        },
    }

    local report = vulns.Report:new(SCRIPT_NAME, host, port)
    local version = get_jenkins_version(host, port)
    
    if version then
        if is_vulnerable(version) then
            vuln_table.state = vulns.STATE.LIKELY_VULN
        end
        vuln_table.extra_info = string.format("Detected Jenkins version: %s", version)
    else
        vuln_table.state = vulns.STATE.UNKNOWN
        vuln_table.extra_info = "Could not determine Jenkins version"
    end

    return report:make_output(vuln_table)
end
