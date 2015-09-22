#!/usr/bin/lua
-- Grab host status and dump it as a json object.

print ("Content-type: application/json")
print ("Access-Control-Allow-Origin: *");
print ("Access-Control-Allow-Methods: GET, POST");
print ("Access-Control-Allow-Headers: X-Requested-With\n");

-- Get a list of all the extant devices:
-- This comes from a set of files under /var/state/ndp/neighbors
-- that is populated by ndp.   Each file has the name of the host's
-- link-local address, and contains one or more lines.   Each line
-- either starts with 4: for an IPv4 address, 6: for an IPv6 address,
-- or l: for the last-seen time expressed in seconds since the epoch
-- according to the local clock.
hosts = {}

local p = assert(io.popen("find /var/state/ndp/neighbors -type f -print"))
for filename in p:lines() do
  local lladdr = string.sub(filename, string.find(filename, "[^/]*$"))

  local sixaddrs = {}
  local nsa = 1
  local fouraddrs = {}
  local nfa = 1
  local lastheard = nil

  local f = assert(io.open(filename))
  for line in f:lines() do
    local t = string.sub(line, string.find(line, "^[^:]+"))
    local d = string.gsub(string.sub(line, string.find(line, "[^:]+$")), "^%s*", "")
    if t == "4" then
      fouraddrs[nfa] = d
      nfa = nfa + 1
    elseif t == "6" then
      sixaddrs[nsa] = d
      nsa = nsa + 1
    elseif t == "l" then
      lastheard = os.time() - tonumber(d)
    end
  end
  f:close()
  local host = { }
  if nfa > 1 then
     host["v4addrs"] = fouraddrs
  end
  if nsa > 1 then
    host["v6addrs"] = sixaddrs
  end
  if lastheard ~= nil then
    host["lastheard"] = lastheard
  end
  hosts[lladdr] = host
end
p:close()

-- parse the DHCP lease table and update the host entries accordingly
local f = assert(io.open("/tmp/dhcp.leases"))
for line in f:lines() do
  -- Each line is composed of the lease expiry time, MAC address, IP address,
  -- hostname and client identifier, all separated by spaces, e.g.:
  -- 1435316749 6c:40:08:96:74:8c 192.168.1.218 sarasvati 01:6c:40:08:96:74:8c

  local i = 1
  local leasetime = nil
  local lladdr = nil
  local ipaddr = nil
  local name = nil
  local clid = nil

  for chunk in string.gmatch(line, "%S+") do
    if i == 1 then
      leasetime = tonumber(chunk) - os.time()
   elseif i == 2 then
      lladdr = chunk
    elseif i == 3 then
      ipaddr = chunk
    elseif i == 4 then
      name = chunk
    elseif i == 5 then
      clid = chunk
    -- It's possible that the name contains a space, in which case
    -- we'll have more than five chunks, the last of which is the
    -- client identifier, which means that what we thought was the
    -- client identifier was actually part of the name.
    elseif i > 5 then
      name = name .. " " .. clid
      clid = chunk
    end
    i = i + 1
  end
  if not (lladdr == nil) then
    host = hosts[lladdr]
    if host == nil then
      host = {}
      hosts[lladdr] = host
    end
    if ipaddr ~= nil then
      host["leased-v4addr"] = ipaddr
      local ipmatch = false
      local v4addrs = host["v4addrs"]
      if v4addrs ~= nil then
        for i, addr in ipairs(v4addrs) do
	  if addr == ipaddr then
	    ipmatch = true
	  end
	end
	if not ipmatch then
	  table.insert(v4addrs, ipaddr)
	end
      end
    end
    host["lease-time"] = leasetime
    host["description"] = name
    host["dhcpv4-client-identifier"] = clid
  end
end
f:close()
  
local oosep = "[\n"
for lladdr in pairs(hosts) do
  io.write(oosep .. "  { \"device\": \"" .. lladdr .. "\"")
  oosep = ",\n"
  local osep = ",\n"
  local host = hosts[lladdr]
  for key in pairs(host) do
    local thunk = host[key]
    if key == "v4addrs" or key == "v6addrs" then
      io.write(osep .. "    \"" .. key .. "\":")
      local sep = "["
      for i = 1, table.getn(thunk) do
	io.write(sep .. "\"" .. thunk[i] .. "\"")
	sep = ", "
      end
      io.write("]")
    elseif type(thunk) == "number" then
      io.write(osep .. "    \"" .. key .. "\": " .. tostring(thunk))
    else
      io.write(osep .. "    \"" .. key .. "\": \"" .. thunk .. "\"")
    end
  end
  io.write("}")
end

io.write("]\n")
