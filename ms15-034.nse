-- The Head Section --
description =  "Script to detect MS15-034 on HTTP port"
author = "Prajwal Panchmahalkar"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "safe"}

local shortport = require "shortport"
local http = require "http"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table  = require "table"

-- The Rule Section --
portrule = shortport.http

-- The Action Section --
action = function(host, port)
    local status, err, responseData
    local socket = nmap.new_socket()
    local status,err = socket:connect(host, port)

    status, err = socket:send("GET / HTTP/1.1\r\nHost: stuff\r\nRange: bytes=0-18446744073709551615\r\n\r\n")
    local status,responseData = socket:receive(1024)
    local checkstring = string.match(responseData,"Error 416")
    if checkstring then
        return "Possibly to be vulnerable to MS15-0034!!"
    end
end
