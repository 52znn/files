--[[
#-------------------------------------------------------------------
# 宝塔Linux面板
#-------------------------------------------------------------------
# Copyright (c) 2015-2099 宝塔软件(http://bt.cn) All rights reserved.
#-------------------------------------------------------------------
# Author: 梁凯强 <1249648969@qq.com>
# 宝塔Nginx防火墙
# OUT_Time: 2022-05-20
# 祝福大家 2022年一直开心一直快乐,在新的一年中更加美好！！！！  

  ┏┛ ┻━━━━━┛  ┻┓
  ┃　　　━　　 ┃
  ┃　┳┛　  ┗┳  ┃
  ┃　　　-　　 ┃
  ┗━┓　　　┏━━━┛   佛祖保佑、没有bug
    ┃　　　┗━━━━━━━━┓
    ┗━┓ ┓ ┏━━━┳ ┓ ┏━┛
      ┗━┻━┛   ┗━┻━┛
]]--
local cpath = "/www/server/btwaf/"
local cpath2 = "/dev/shm/"
local jpath = cpath .. "rule/"
local json = require "cjson"
local cmspath = cpath .. "cms/"
local ngx_match = ngx.re.find
local resolver = require "dns"
local libinjection = require "libinjection"
local multipart = require "multipart"
--local lsqlite3 = require "lsqlite3"
local error_rule = nil
local is_type =nil
local today =os.date("%Y-%m-%d")

local function get_ip_position_data(ip)
    local ok ,geo = pcall(function()
        			return  require 'maxminddb'
        		end)
	if not ok then
	    return nil
    end
	if type(geo)=='number' then return nil end
    if not geo.initted() then
            geo.init("/www/server/btwaf/GeoLite2-City.mmdb")
    end
    local res,err=geo.lookup(ip or ngx.var.remote_addr)
    if not res then
            return nil
    else
        return res
    end
end

local function arrip(ipstr)
	if ipstr == 'unknown' then return {0,0,0,0} end
	if string.find(ipstr,':') then return ipstr end
	iparr = split(ipstr,'.')
	iparr[1] = tonumber(iparr[1])
	iparr[2] = tonumber(iparr[2])
	iparr[3] = tonumber(iparr[3])
	iparr[4] = tonumber(iparr[4])
	return iparr
end

function is_min(ip1,ip2)
	if not ip1 then return false end
	if not ip2 then return false end
	n = 0
	for _,v in ipairs({1,2,3,4})
	do
		if  not ip1[v] then return false end 
		if  not ip2[v] then return false end 
		if ip1[v] == ip2[v] then
			n = n + 1
		elseif ip1[v] > ip2[v] then
			break
		else
			return false
		end
	end
	return true
end

function is_max(ip1,ip2)
	if not ip1 then return false end
	if not ip2 then return false end
	n = 0
	for _,v in ipairs({1,2,3,4})
	do
		if  not ip1[v] then return false end 
		if  not ip2[v] then return false end 
		if ip1[v] == ip2[v] then
			n = n + 1
		elseif ip1[v] < ip2[v] then
			break
		else
			return false
		end
	end
	return true
end

local function is_intranet_address(ips)
	if not ips then return false end
	if ips=='unknown' then return false end 
	if string.find(ips,':') then return false end
	ips = arrip(ips)
	if (not is_max(ips,arrip("192.168.255.255")) and not is_min(ips,arrip("192.168.0.1"))) and  (not is_max(ips,arrip("172.16.255.255")) and not is_min(ips,arrip("172.16.0.1"))) and (not is_max(ips,arrip("10.255.255.255")) and not is_min(ips,arrip("10.0.0.1")))  then return false end
	return true
end

local function check_dir(path)
	local file = io.open(path, "rb")
	if file then file:close() end
	return file ~= nil
end

local function create_dir(path)
	os.execute("mkdir -p " .. path)
end


local function btwaf_init_db()
    local ok ,sqlite3 = pcall(function()
        			return  require "lsqlite3"
        		end)
	if not ok then
	    return false
    end
	if totla_log_db  then return false end
    local path = cpath .. '/totla_db/'
	if not check_dir(path) then create_dir(path) end
	if not check_dir('/www/server/btwaf/totla_db/http_log') then create_dir('/www/server/btwaf/totla_db/http_log') end
	local db_path = path.."totla_db.db"
	if totla_log_db == nil or not totla_log_db:isopen() then
		totla_log_db = sqlite3.open(db_path)
	end
	if totla_log_db==nil then return false end 
	table_name = "totla_db"
	local stmt = totla_log_db:prepare("SELECT COUNT(*) FROM sqlite_master where type='table' and name=?")
	local rows = 0
	if stmt ~= nil then
		stmt:bind_values(table_name)
		stmt:step()
		rows = stmt:get_uvalues()
		stmt:finalize()
	end
	if stmt == nil or rows == 0 then
		status, errorString = totla_log_db:exec([[PRAGMA synchronous = 0]])
		status, errorString = totla_log_db:exec([[PRAGMA page_size = 4096]])
		status, errorString = totla_log_db:exec([[PRAGMA journal_mode = wal]])
		status, errorString = totla_log_db:exec([[PRAGMA journal_size_limit = 1073741824]])
		status,errorString = totla_log_db:exec[[
			CREATE TABLE btwaf_msg (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				server_name TEXT,
				time INTEGER,
				time_localtime TEXT,
		)]]
		status,errorString = totla_log_db:exec[[
			CREATE TABLE totla_log (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				time INTEGER,
				time_localtime TEXT,
				server_name TEXT,
				ip TEXT,
				ip_city TEXT,
				ip_country TEXT,
				ip_subdivisions TEXT,
				ip_continent TEXT,
				ip_longitude TEXT,
				ip_latitude TEXT,
				type TEXT,
				uri TEXT,
				user_agent TEXT,
				filter_rule TEXT,
				incoming_value TEXT,
			    value_risk TEXT,
				http_log TEXT,
				http_log_path INTEGER
			)]]
		status, errorString = totla_log_db:exec([[CREATE INDEX id_inx ON totla_log(id)]])
		status, errorString = totla_log_db:exec([[CREATE INDEX time_inx ON totla_log(time)]])
        status,errorString = totla_log_db:exec[[
			CREATE TABLE blocking_ip (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
			    time INTEGER,
				time_localtime TEXT,
				server_name TEXT,
				ip TEXT,
				ip_city TEXT,
				ip_country TEXT,
				ip_subdivisions TEXT,
				ip_continent TEXT,
				ip_longitude TEXT,
				ip_latitude TEXT,
				type TEXT,
				uri TEXT,
				user_agent TEXT,
				filter_rule TEXT,
				incoming_value TEXT,
			    value_risk TEXT,
				http_log TEXT,
				http_log_path INTEGER,
				blockade TEXT,
				blocking_time INTEGER,
				is_status INTEGER
			)]]
		status, errorString = totla_log_db:exec([[CREATE INDEX id_inx ON blocking_ip(id)]])
		status, errorString = totla_log_db:exec([[CREATE INDEX time_inx ON blocking_ip(time)]])
	end
end

local function totla_log_insert(is_log,server_name,ip,type,uri,user_agent,filter_rule,incoming_value,value_risk,http_log,blockade,blocking_time)
	if filter_rule==nil then filter_rule='目录保护' end
	btwaf_init_db()
	if totla_log_db==nil then return false end 
	if is_log=='log' then 
	   totla_log_db_insert=totla_log_db
	   stmt2 = totla_log_db_insert:prepare[[INSERT INTO totla_log(
    		time,time_localtime,server_name,ip, ip_city,ip_country,ip_subdivisions,ip_continent,ip_longitude,ip_latitude,type,uri,user_agent,filter_rule,incoming_value,value_risk,http_log,http_log_path) 
    		VALUES(:time,:time_localtime,:server_name,:ip,:ip_city,:ip_country,:ip_subdivisions,:ip_continent,:ip_longitude, :ip_latitude,:type,:uri,:user_agent,:filter_rule,:incoming_value,:value_risk,:http_log,:http_log_path)]]
        if stmt2 == nil then return return_message(200,'log_error') end
	elseif is_log=='ip' then 
	     totla_log_db_insert=totla_log_db
	      stmt2 = totla_log_db_insert:prepare[[INSERT INTO blocking_ip(
    		time,time_localtime,server_name,ip, ip_city,ip_country,ip_subdivisions,ip_continent,ip_longitude,ip_latitude,type,uri,user_agent,filter_rule,incoming_value,value_risk,http_log,http_log_path,blockade,blocking_time,is_status) 
    		VALUES(:time,:time_localtime,:server_name,:ip,:ip_city,:ip_country,:ip_subdivisions,:ip_continent,:ip_longitude,:ip_latitude,:type,:uri,:user_agent,:filter_rule,:incoming_value,:value_risk,:http_log,:http_log_path,:blockade,:blocking_time,:is_status)]]
	    if stmt2 == nil then return return_message(200,'ip_error') end
	end
	log_http=ngx.md5(http_log)
	status, errorString = totla_log_db_insert:exec([[BEGIN TRANSACTION]])
	get_ip_position=get_ip_position_data(ip)
    if 	get_ip_position==nil then 
          if  is_intranet_address(ip) then 
            ip_city=''
            ip_country='内网地址'
            ip_subdivisions=''
            ip_continent=''
            ip_longitude=''
            ip_latitude=''
        else
            ip_city=''
            ip_country='未知位置'
            ip_subdivisions=''
            ip_continent=''
            ip_longitude=''
            ip_latitude=''
        end
    else
        if get_ip_position['city'] then 
            if get_ip_position['city']['names'] then 
                ip_city=get_ip_position['city']['names']['zh-CN']
            else
                 ip_city=''
            end 
        end
        if get_ip_position['country'] then 
            if get_ip_position['country']['names'] then 
                ip_country=get_ip_position['country']['names']['zh-CN']
            else
                ip_country=''
            end 
        end
        if get_ip_position['subdivisions'] then 
            if get_ip_position['subdivisions'][1] then 
                ip_subdivisions=get_ip_position['subdivisions'][1]['names']['zh-CN']
            else
                ip_subdivisions=''
            end
        end
        if get_ip_position['continent'] then 
            if get_ip_position['continent'] then 
                ip_continent=get_ip_position['continent']['names']['zh-CN']
            else
                ip_continent=''
            end
        end
        if get_ip_position['location'] then 
            if get_ip_position['location'] then 
                ip_longitude=get_ip_position['location']['longitude']
            else
                ip_longitude=''
            end 
            
        end
        if get_ip_position['location'] then 
            if get_ip_position['location'] then 
                ip_latitude=get_ip_position['location']['latitude']
            else
                ip_latitude=''
            end 
        end
    end
    if ngx.req.get_method()=='POST' then
        http_log_path=1
        http_log_body='/www/server/btwaf/totla_db/http_log/'..ngx.md5(http_log)..'.log'
    else
        http_log_path=0
        http_log_body=http_log
    end 
    
    if is_log=='log' then 
    	stmt2:bind_names{
    		time=os.time(),
    		time_localtime=ngx.localtime(),
    		server_name=server_name,
    	    ip=ip,
    	    ip_city=ip_city,
    	    ip_country=ip_country,
    	    ip_subdivisions=ip_subdivisions,
    	    ip_continent=ip_continent,
    	    ip_longitude=ip_longitude,
    	    ip_latitude=ip_latitude,
    	    type=type,
    	    uri=uri,
    	    user_agent=user_agent,
    	    filter_rule=filter_rule,
    	    incoming_value=incoming_value,
    	    value_risk=value_risk,
    	    http_log=http_log_body,
    	    http_log_path=http_log_path
    	}
    elseif is_log=='ip' then 
        stmt2:bind_names{
    		time=os.time(),
    		time_localtime=ngx.localtime(),
    		server_name=server_name,
    	    ip=ip,
    	    ip_city=ip_city,
    	    ip_country=ip_country,
    	    ip_subdivisions=ip_subdivisions,
    	    ip_continent=ip_continent,
    	    ip_longitude=ip_longitude,
    	    ip_latitude=ip_latitude,
    	    type=type,
    	    uri=uri,
    	    user_agent=user_agent,
    	    filter_rule=filter_rule,
    	    incoming_value=incoming_value,
    	    value_risk=value_risk,
    	    http_log=http_log_body,
    	    http_log_path=http_log_path,
    	    blockade=blockade,
    	    blocking_time=blocking_time,
    	    is_status=true
	    }
    end 
    
	stmt2:step()
	stmt2:reset()
	stmt2:finalize()
	totla_log_db_insert:execute([[COMMIT]])
	if http_log_path==1 then 
    	local filename = http_log_body
    	local fp = io.open(filename,'wb')
    	if fp == nil then return false end
    	local logtmp = {http_log}
    	local logstr = json.encode(logtmp)
    	fp:write(logstr)
    	fp:flush()
    	fp:close()
    end 
end

local function read_file(name)
    fbody = read_file_body(jpath .. name .. '.json')
    if fbody == nil then
        return {}
    end
    return json.decode(fbody)
end

local function write_file2(filename,body)
	fp = io.open(filename,'a+')
	if fp == nil then
        return nil
    end
	fp:write(body)
	fp:flush()
	fp:close()
	return true
end

local function logs(data)
    write_file2('/dev/shm/btwaf.json',"\n"..data.."\n")
end 

function read_file_body(filename)
	fp = io.open(filename,'r')
	if fp == nil then
        return nil
    end
	fbody = fp:read("*a")
    fp:close()
    if fbody == '' then
        return nil
    end
	return fbody
end

local function re_png(filename)
	fp = io.open(filename,'rb')
	if fp == nil then
        return nil
    end
	fbody = fp:read("*a")
    fp:close()
    if fbody == '' then
        return nil
    end
	return fbody
end

local function write_file(filename,body)
	fp = io.open(filename,'w')
	if fp == nil then
        return nil
    end
	fp:write(body)
	fp:flush()
	fp:close()
	return true
end

function bt_ip_filter(ip,time_out)
    local bt_ip_filter='/dev/shm/.bt_ip_filter'
    local fp = io.open(bt_ip_filter,'rb')
    local token_key = 'bt_ip_filter_ip_list'
    local dony_ip = '+,'..ip..','..tostring(time_out)
	if fp == nil then
        local tbody = ngx.shared.btwaf:get(token_key)
        if not tbody then
            tbody = dony_ip
        else
            tbody = tbody .. "\n" .. dony_ip
        end
        write_file(bt_ip_filter,tbody)
		ngx.shared.btwaf:delete(token_key)
    else
        local tbody = ngx.shared.btwaf:get(token_key)
        if not tbody then 
             tbody = dony_ip
        else
            tbody = tbody .."\n".. dony_ip
        end
        ngx.shared.btwaf:set('bt_ip_filter_ip_list',tbody,3600)
    end
end 

local config = json.decode(read_file_body(cpath .. 'config.json'))
waf_config_data=config
local site_config = json.decode(read_file_body(cpath .. 'site.json'))
waf_site_config =site_config
local function is_ipaddr(client_ip)
	if string.find(client_ip,':') then return true end
	local cipn = split(client_ip,'.')
	if arrlen(cipn) < 4 then return false end
	for _,v in ipairs({1,2,3,4})
	do
		local ipv = tonumber(cipn[v])
		if ipv == nil then return false end
		if ipv > 255 or ipv < 0 then return false end
	end
	return true
end

local function compare_ip_block(ips)
	if (string.match(ips,"^%d+%.%d+%.%d+%.%d+$") == nil and string.match(ips,"^[%w:]+$") == nil) or ips == 'unknown'  then return false end
	if not ips then return false end
	if ips=='unknown' then return false end 
	if string.find(ips,':') then return false end
	ips = arrip(ips)
	if not is_max(ips,arrip("127.0.0.255")) then return false end
	if not is_min(ips,arrip("127.0.0.1")) then return false end
	return true
end

local function split_bylog( str,reps )
	local resultStrList = {}
	string.gsub(str,'[^'..reps..']+',function(w)
		table.insert(resultStrList,w)
	end)
	return resultStrList
end

local function get_client_ip_bylog()
	local client_ip = "unknown"
	if site_config[server_name] then
		if site_config[server_name]['cdn'] then
			for _,v in ipairs(site_config[server_name]['cdn_header'])
			do
				if request_header[v] ~= nil and request_header[v] ~= "" then
					local header_tmp = request_header[v]
					if type(header_tmp) == "table" then header_tmp = header_tmp[1] end
					tmpe=split_bylog(header_tmp,',')
                    if arrlen(tmpe)>=1 then 
                        if site_config[server_name]['cdn_baidu'] ~=nil and site_config[server_name]['cdn_baidu'] then 
                            client_ip=tmpe[1]
    				        client_ip=string.gsub(client_ip," ","")
                        else
    				        client_ip=tmpe[arrlen(tmpe)]
    				        client_ip=string.gsub(client_ip," ","")
				        end 
						if request_header['remote-host'] and request_header['remote-host']~=nil then 
							if request_header['remote-host']==client_ip then 
								client_ip=tmpe[1]
								client_ip=string.gsub(client_ip," ","")
							end 
						end 
				    end
					if compare_ip_block(client_ip) then
						if tostring(ngx.var.remote_addr) == tostring(client_ip) then
							client_ip = ngx.var.remote_addr
						else
							client_ip = ngx.var.remote_addr
						end
					end
					break;
				end
			end
		end
	end
	if type(client_ip) == 'table' then client_ip = "" end
	if (string.match(client_ip,"^%d+%.%d+%.%d+%.%d+$") == nil and string.match(client_ip,"^[%w:]+$") == nil) or client_ip == 'unknown'  then
		client_ip = ngx.var.remote_addr
		if client_ip == nil then
			client_ip = "unknown"
		end
	end
	if not ngx.shared.btwaf_data:get(client_ip) then 
	    ngx.shared.btwaf_data:set(client_ip,0,3600)
	end
	return client_ip
end




function split( str,reps )
    if str ==nil then return nil end 
    local resultStrList = {}
    string.gsub(str,'[^'..reps..']+',function(w)
        table.insert(resultStrList,w)
    end)
    return resultStrList
end

local function join(arr,e)
	result = ''
	length = arrlen(arr)
	for k,v in ipairs(arr)
	do
		if length == k then e = '' end
		result = result .. v .. e
	end
	return result
end

function arrlen(arr)
	if not arr then return 0 end
	count = 0
	for _,v in ipairs(arr)
	do
		count = count + 1
	end
	return count
end

local function select_rule(rules)
	if not rules then return {} end
	new_rules = {}
	for i,v in ipairs(rules)
	do 
		if v[1] == 1 then
			table.insert(new_rules,v[2])
		end
	end
	return new_rules
end

local function select_rule_args(rules)
	if not rules then return {} end
	new_rules = {}
	for i,v in ipairs(rules)
	do 
		if v[1] == 1 then
		    new_rules2 = {}
		    table.insert(new_rules2,v[2])
		    table.insert(new_rules2,v[3])
		    if v[5]~=nil then 
		        table.insert(new_rules2,v[5])
		    else
		        table.insert(new_rules2,100)
		    end
			table.insert(new_rules,new_rules2)
		end
	end
	return new_rules
end

function is_site_config(cname)
	if site_config[server_name] ~= nil then
		if cname == 'cc' then
			return site_config[server_name][cname]['open']
		else
			return site_config[server_name][cname]
		end
	end
	return true
end


local function return_message(status,msg)
	ngx.header.content_type = "application/json;"
	ngx.header.Cache_Control = "no-cache"
	ngx.status = status
	ngx.say(json.encode(msg))
    ngx.exit(status)
end

local function get_boundary()
    local header = request_header["content-type"]
    if not header then return nil end
    if type(header) == "table" then
        return return_message(200,'content-type ERROR')
    end
	if header then
    	if ngx.re.find(header,[[multipart]],'ijo') then
    		if not ngx.re.match(header,'^multipart/form-data; boundary=') then 
    				return return_message(200,'content-type ERROR')
    		end
    	   multipart_data=ngx.re.match(header,'^multipart/form-data; boundary=.+')
    	   if not multipart_data then return return_message(200,"Btwaf  Boundary  Error") end
    	    if ngx.re.match(multipart_data[0],'""') then 
    	        return return_message(200,"Btwaf  Boundary Double Quotation Mark Error")
    	    end 
    		check_file=ngx.re.gmatch(multipart_data[0],[[=]],'ijo')
	        ret={}
	        while true do
    		    local m, err = check_file()
    	      	if m then 
    	      		table.insert(ret,m)
    	      	else
    	      		break
    	      	end 
	        end
	        if type(ret)~='table' then return false end 
	        if(arrlen(ret)>=2) then
	            return return_message(200,"multipart/form-data ERROR")
	        end
    		return header
    	else
    		return false
    	end 
    end 
end

local function count_sieze(data)
    local count=0
    if type(data)~="table" then return count end 
	for k,v in pairs(data) 
	do
	    count=count+1
	end 
	return count
end 


local ip_html = read_file_body(config["reqfile_path"] .. '/' .. 'ip.html')
local url_html = read_file_body(config["reqfile_path"] .. '/' .. 'url.html')
local get_html = read_file_body(config["reqfile_path"] .. '/' .. config["get"]["reqfile"])
local post_html = read_file_body(config["reqfile_path"] .. '/' .. config["post"]["reqfile"])
local cookie_html = read_file_body(config["reqfile_path"] .. '/' .. config["cookie"]["reqfile"])
local user_agent_html = read_file_body(config["reqfile_path"] .. '/' .. config["user-agent"]["reqfile"])
local other_html = read_file_body(config["reqfile_path"] .. '/' .. config["other"]["reqfile"])
local cnlist = json.decode(read_file_body(cpath .. '/rule/cn.json'))
local lanlist = json.decode(read_file_body(cpath .. '/rule/lan.json'))
local scan_black_rules = read_file('scan_black')
local ip_black_rules = read_file('ip_black')
local ip_white_rules = read_file('ip_white')
local url_white_rules = read_file('url_white')
local cc_uri_white_rules = read_file('cc_uri_white')
local url_black_rules = read_file('url_black')
local user_agent_rules = select_rule(read_file('user_agent'))
local post_rules = select_rule_args(read_file('post'))
local cookie_rules = select_rule(read_file('cookie'))
local args_rules = select_rule_args(read_file('args'))
local url_rules = select_rule(read_file('url'))
local head_white_rules = read_file('head_white')
local referer_local = select_rule(read_file('referer'))
local captcha_num2 = json.decode(read_file_body('/www/server/btwaf/captcha/num2.json'))
local shell_check = json.decode(read_file_body('/www/server/btwaf/shell_check.json'))




local function return_html(status,html)
	ngx.header.content_type = "text/html"
	ngx.header.Cache_Control = "no-cache"
    ngx.status = status
    ngx.say(html)
    ngx.exit(status)
end

local function get_return_state(rstate,rmsg)
	result = {}
	result['status'] = rstate
	result['msg'] = rmsg
	return result
end



local function gusb_string(table)
	ret={"-","]","@","#","&","_","{","}"}
	ret2={}
	if arrlen(table)==0 then return table end 
	for _,v in pairs(table) do
		for _,v2 in pairs(ret) do 
			if ngx.re.find(v[0],v2) then 
				v[0]=ngx.re.gsub(v[0],v2,'baota')
			end
		end
		v[0]=string.gsub(v[0],'%[','baota')
		v[0]=string.gsub(v[0],'%(','baota')
		v[0]=string.gsub(v[0],'%)','baota')
		v[0]=string.gsub(v[0],'%+','baota')
		v[0]=string.gsub(v[0],'%$','baota')
		v[0]=string.gsub(v[0],'%?','baota')
	end
	return table
end 


local function  return_html_data(title,t1,li,l2)
	local check_html = [[<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>]]..title..[[</title>
<style>
*{margin:0;padding:0;color:#444}
body{font-size:14px;font-family:"宋体"}
.main{width:600px;margin:10% auto;}
.title{background: #20a53a;color: #fff;font-size: 16px;height: 40px;line-height: 40px;padding-left: 20px;}
.content{background-color:#f3f7f9; height:280px;border:1px dashed #c6d9b6;padding:20px}
.t1{border-bottom: 1px dashed #c6d9b6;color: #ff4000;font-weight: bold; margin: 0 0 20px; padding-bottom: 18px;}
.t2{margin-bottom:8px; font-weight:bold}
ol{margin:0 0 20px 22px;padding:0;}
ol li{line-height:30px}
</style>
</head>

<body>
	<div class="main">
		<div class="title">]]..title..[[</div>
		<div class="content">
			<p class="t1">]]..t1..[[</p>
			<p class="t2">可能原因：</p>
			<ol>
				<li>]]..li..[[</li>
			</ol>
			<p class="t2">如何解决：</p>
			<ol>
				<li>]]..l2..[[</li>
			</ol>
		</div>
	</div>
</body>
<!--8.6.0 -->
</html>
]]
    		ngx.header.content_type = "text/html;charset=utf8"
    		ngx.header.Cache_Control = "no-cache"
    		ngx.say(check_html)
    		ngx.exit(200)
end

local function is_body_intercept(body)
    if not config['open'] or not is_site_config('open') then return false end
    if not config['body_intercept'] then return false end 
    if arrlen(config['body_intercept'])==0  then return false end
    if config['body_intercept'] then
		for __,v in pairs(config['body_intercept'])
		do
			if ngx.re.match(ngx.unescape_uri(body),v) then
				return_html_data('禁止存在违禁词','禁止存在违禁词','禁止存在违禁词'..'【'..v..'】','禁止存在违禁词'..'【'..v..'】')
			end
		end
	end
end

local function data_in_php(data)
	if not data then
		return false
	else
		if ngx.re.find(data,[[<\?php]],'ijo') then
		    is_type='webshell防御'
		    error_rule="非法上传php文件被系统拦截"
		    write_log('post','非法上传')
			return_html(config['post']['status'],cookie_html)
			return true
		else
			return false
		end
	end
end

local function Verification_auth_btwaf()
	local token = ngx.md5(ip..'auth')
	local count,_ = ngx.shared.btwaf:get(token)
	if count then
		if count > config['retry'] then
			local safe_count,_ = ngx.shared.drop_sum:get(ip)
			if not safe_count then
				ngx.shared.drop_sum:set(ip,1,86400)
				safe_count = 1
			else
				ngx.shared.drop_sum:incr(ip,1)
			end
			local lock_time = (config['retry_time'] * safe_count)
			if lock_time > 86400 then lock_time = 86400 end
			ngx.shared.drop_ip:set(ip,retry+1,lock_time)
			is_type='cc'
			lan_ip('cc','防火墙验证码接口遭到该IP攻击:  '..cycle..'秒内累计超过'..config['retry']..'次请求,封锁' .. lock_time .. '秒')
		else
			ngx.shared.btwaf:incr(token,1)
		end
	else
		ngx.shared.btwaf:set(token,1,config['retry_cycle'])
	end
	num2=ngx.shared.btwaf:get(ip..'__captcha')
	if num2 ==nil then  return get_return_state(false,'验证码已经过期') end
	if uri_request_args['captcha'] then
		if num2 ==string.lower(uri_request_args['captcha']) then
            local token=''
            if request_header['user-agent']~=nil then 
            	token=ngx.md5(ip..request_header['user-agent']..server_name..'code'..today)
            else
            	token=ngx.md5(ip..server_name..'code'..today)
            end 
            jwt_value=ngx.md5(os.time()..ip)
            ngx.shared.btwaf:set(token,jwt_value,7200)
            ngx.header.Set_Cookie =token.."="..jwt_value..';'
			return get_return_state(true,'验证成功')
		else
			return get_return_state(false,'验证码错误')
		end 
	end
	return get_return_state(false,'请填写验证码')
end


local function continue_key(key)
    if method~='POST' then return true end  
	key = tostring(key)
	if string.len(key) > 64 then return false end;
	local keys = {"content","contents","body","msg","file","files","img","newcontent","message","subject","kw","srchtxt",""}
	for _,k in ipairs(keys)
	do
		if k == key then return false end;
	end
	return true;
end


local function select_rule2(is_type,rule)
    if is_type =='post' or is_type=='args' or is_type=='url' then
        local post_rules2 =read_file(is_type)
    	if not post_rules2 then return nil end
    	for i,v in ipairs(post_rules2)
    	do 
    		if v[1] == 1 then
    		    if v[2]==rule then 
    		        return v[3]
    		        
    		    end
    		end
    	end
    end
	return nil
end

local function is_type_return(is_type,rule,static)
    if is_type ~='post' and is_type~='args' and is_type~='url'  then return nil end 
    if static=='static' then 
        data=select_rule2(is_type,rule)
    elseif static=='ip' then 
        data=rule
    end 
    if data==nil then return nil end 
    if data=='目录保护1' or data=='目录保护2' or data=='目录保护3' then return "目录保护" end 
    if data=='PHP流协议过滤1' then return "PHP流协议" end 
    if  data=='一句话*屏蔽的关键字*过滤1' or  data=='一句话*屏蔽的关键字*过滤2' or data=='一句话木马过滤1' or data=='一句话木马过滤3' or data=='一句话*屏蔽的关键字*过滤3' or data=='菜刀流量过滤' then return 'PHP函数' end
    if data=='SQL注入过滤2' or data=='SQL注入过滤1' or data=='SQL注入过滤3' or data=='SQL注入过滤4' or data=='SQL注入过滤5' or data=='SQL注入过滤6'  then return "SQL注入"  end 
    if data=='SQL注入过滤7' or data=='SQL注入过滤9' or data=='SQL注入过滤8' or data=='SQL注入过滤10' or data=='test' then return 'SQL注入' end 
    if data=='SQL报错注入过滤01' or data=='SQL报错注入过滤02' then return 'SQL注入' end
    if data=='一句话木马过滤5' or data=='一句话木马过滤4' then return 'PHP脚本过滤' end
    if data=="" then return 'SQL注入' end
    if data=='XSS过滤1' then return 'XSS攻击' end
    if data=='ThinkPHP payload封堵' then return 'ThinkPHP攻击' end
    if data=='文件目录过滤1' or data=='文件目录过滤2' or data=='文件目录过滤3' then return '目录保护' end
    if data=='PHP脚本执行过滤1' or data=='PHP脚本执行过滤2' then return 'PHP脚本过滤' end
    return data
end

local function is_ngx_match(rules,sbody,rule_name)
	if rules == nil or sbody == nil then return false end
	if type(sbody) == "string" then
		sbody = {sbody}
	end
	
	if type(rules) == "string" then
		rules = {rules}
	end
	for k,body in pairs(sbody)
    do  
        
		if continue_key(k) then
			for i,rule in ipairs(rules)
			do
				if site_config[server_name] and rule_name then
					local n = i - 1
					for _,j in ipairs(site_config[server_name]['disable_rule'][rule_name])
					do
						if n == j then
							rule = ""
						end
					end
				end
				if body and rule ~="" then
					if type(body) == "string" and type(rule) == "string" then
						if ngx_match(ngx.unescape_uri(body),rule,"isjo") then
						    is_type =is_type_return(rule_name,rule,"static")
							error_rule = rule .. ' >> ' .. k .. '=' .. body.. ' >> ' .. body
							return true
						end
					elseif type(body) == "string" and type(rule) == "table" then
					    if ngx_match(ngx.unescape_uri(body),rule[1],"isjo") then
						    is_type =is_type_return(rule_name,rule[2],"ip")
							error_rule = rule[1] .. ' >> ' .. k .. '=' .. body.. ' >> ' .. body
							return true
						end
					end
				end
			end
		end
	end
	return false
end


local function ip2long(str)
	local num = 0
	if str and type(str)=="string" then
		local o1,o2,o3,o4 = str:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")
		if o1 == nil or o2 == nil or o3 == nil or o4 == nil then return 0 end
		num = 2^24*o1 + 2^16*o2 + 2^8*o3 + o4
	end
    return num
end


local function compare_ip2(ips)
	if ip == 'unknown' then return false end
	if string.find(ip,':') then return false end
	if  type(ips[2])~='number' and  type(ips[1])~='number' and  type(ipn2)~='number' then  return false end
	if  ipn2<=ips[2] and ipn2>=ips[1] then return true end 
	return false
end

local function get_id()
    local total_path = cpath .. 'total.json'
	local tbody = ngx.shared.btwaf:get(total_path)
	if not tbody then
		tbody = read_file_body(total_path)
		if not tbody then return 0 end
	end
	local total = json.decode(tbody)
	if not total['total'] then total['total'] = 0 end
	total['total'] = total['total'] + 1
    return total['total']
end 

local function http_log()
    data=''
    data=method..' ' ..request_uri.. ' '..  'HTTP/1.1\n'
    if not ngx.req.get_headers(20000) then return data end
    for key,valu in pairs(ngx.req.get_headers(20000)) do 
        if type(valu)=='string' then 
            data=data..key..':'..valu..'\n'
        end
		if type(valu) =='table' then
            for key2,val2 in pairs(valu) do
                data=data..key..':'..val2..'\n'
            end 
        end
    end
    data=data..'\n'
    if method ~='GET' then 
        ngx.req.read_body()
        if get_boundary() then
            if ngx.req.get_body_data() then 
                data =data ..ngx.req.get_body_data()
            else
		        if config['http_open'] then 
	            	request_args2=ngx.req.get_body_file()
    		    	request_args2=read_file_body(request_args2)
    		    	data =data ..request_args2
    		    else
    		       data =data ..'\n拦截非法恶意上传文件或者非法from-data传值,该数据包较大系统默认不存储,如需要开启,请在[Nginx防火墙-->全局配置-->HTTP包]'
    		    end
            end
            return data
        else
	        request_args = ngx.req.get_post_args(1000000)
	        if ngx.req.get_headers(20000)["content-type"] and  ngx.re.find(ngx.req.get_headers(20000)["content-type"], '^application/json',"oij") then
        		local ok ,request_args = pcall(function()
        			return json.decode(ngx.req.get_body_data())
        		end)
        		if not ok then
        			local check_html = [[<html><meta charset="utf-8" /><title>json格式错误</title><div>请传递正确的json参数</div></html>]]
        			ngx.header.content_type = "text/html;charset=utf8"
        			ngx.header.Cache_Control = "no-cache"
        			ngx.say(check_html)
        			ngx.exit(200)
        		end
        		if type(request_args)~='table' then return data end 
        		return data..json.encode(request_args)
            else
	            coun=0
    	        if not request_args then return data end 
        	        for i,v in pairs(request_args) do
        	            if type(v) =='table' then 
        	                for i2,v2 in pairs(v) do 
        	                    if type(v2)=='string' then 
        	                        if coun ==0 then 
        	                            data=data..i..'='..v2
        	                        else
        	                             data=data..'&'..i..'='..v2
        	                        end
        	                        coun=coun+1
        	                    end 
        	                end 
        	            elseif  type(v)=='string' then 
            	            if coun ==0 then 
                                data=data..i..'='..v
                            else
                                 data=data..'&'..i..'='..v
            	            end 
                            coun=coun+1
                        end 
                    end
                    return data
	        end
        end
    else
        return data
    end
end 
local function write_to_file(logstr)
	local filename = config["logs_path"] .. '/' .. server_name .. '_' .. ngx.today() .. '.log'
	local fp = io.open(filename,'ab')
	if fp == nil then return false end
	fp:write(logstr)
	fp:flush()
	fp:close()
	return true
end

local function inc_log(name,rule)
	local total_path = cpath .. 'total.json'
	local tbody = ngx.shared.btwaf:get(total_path)
	if not tbody then
		tbody = read_file_body(total_path)
		if not tbody then return false end
	end
	local total = json.decode(tbody)
	if not total['sites'] then total['sites'] = {} end
	if not total['sites'][server_name] then total['sites'][server_name] = {} end
	if not total['sites'][server_name][name] then total['sites'][server_name][name] = 0 end
	if not total['rules'] then total['rules'] = {} end
	if not total['rules'][name] then total['rules'][name] = 0 end
	if not total['total'] then total['total'] = 0 end
	total['total'] = total['total'] + 1
	total['sites'][server_name][name] = total['sites'][server_name][name] + 1
	total['rules'][name] = total['rules'][name] + 1
	local total_log = json.encode(total)
	if not total_log then return false end
	ngx.shared.btwaf:set(total_path,total_log)
	if not ngx.shared.btwaf:get('b_btwaf_timeout') then
		write_file(total_path,total_log)
		ngx.shared.btwaf:set('b_btwaf_timeout',1,5)
	end
end

local function write_drop_ip2(is_drop,drop_time,name,rule)
	local filename = cpath .. 'drop_ip.log'
	local fp = io.open(filename,'ab')
	if fp == nil then return false end
	if lan_type then lan_type=lan_type end 
	if is_type_rule then lan_type=is_type_rule end 
	if config['send_to'] and config['send_to'] ~='ERROR' then 
    	local logs_data={os.time(),"网站 "..server_name.." 遭到IP "..ip.." 的攻击".."URL为: "..request_uri}
    end
	local logtmp = {os.time(),ip,server_name,request_uri,drop_time,is_drop,method,ngx.var.http_user_agent,name,rule,http_log()}
	totla_log_insert('ip',server_name,ip,method,request_uri,ngx.var.http_user_agent,lan_type,name,'',http_log(),is_drop,drop_time)
	totla_log_insert('log',server_name,ip,method,request_uri,ngx.var.http_user_agent,lan_type,name,'',http_log(),'','')
	bt_ip_filter(ip,drop_time)
	logs(ip..drop_time)
	local logstr = json.encode(logtmp) .. "\n"
	fp:write(logstr)
	fp:flush()
	fp:close()
	inc_log(is_drop,rule)
	return true
end


local function write_log(name,rule)
	local count,_ = ngx.shared.drop_sum:get(ip..today)
	if count then
		ngx.shared.drop_sum:incr(ip..today,1)
	else
		ngx.shared.drop_sum:set(ip..today,1,retry_cycle)
	end
	if config['log'] ~= true or is_site_config('log') ~= true then return false end
	local method = ngx.req.get_method()
	if error_rule then 
		rule = error_rule
		error_rule = nil
	end
	if is_type then 
	    if is_type==nil then 
	        lan_type='目录保护'
	    else
		    lan_type = is_type
		end
		is_type = nil
	end
	local logtmp = {ngx.localtime(),ip,method,request_uri,ngx.var.http_user_agent,name,rule,http_log(),lan_type}
	local logstr = json.encode(logtmp) .. "\n"
	local count,_ = ngx.shared.drop_sum:get(ip..today)	
	if name =='cc' then
	    local safe_count,_ = ngx.shared.drop_sum:get(ip)
        if not safe_count then
        	ngx.shared.drop_sum:set(ip,1,86400)
        	safe_count = 1
        else
        	ngx.shared.drop_sum:incr(ip,1)
        end
        local lock_time = (endtime * safe_count)
        if lock_time > 86400 then lock_time = 86400 end
        ngx.shared.drop_ip:set(ip,retry+1,lock_time)
        ngx.shared.btwaf_data:delete(ip)
	end
	if count > retry-1 and name ~= 'cc' then
		local safe_count,_ = ngx.shared.drop_sum:get(ip)
		if not safe_count then
			ngx.shared.drop_sum:set(ip,1,86400)
			safe_count = 1
		else
			ngx.shared.drop_sum:incr(ip,1)
		end
		local lock_time = retry_time * safe_count
		if lock_time > 86400 then lock_time = 86400 end
		lan_type='封锁此IP'
		
		logtmp = {ngx.localtime(),ip,method,request_uri,ngx.var.http_user_agent,name,retry_cycle .. '秒以内累计超过'..retry..'次以上非法请求,封锁'.. lock_time ..'秒',http_log(),lan_type}
		logstr = logstr .. json.encode(logtmp) .. "\n"
		ngx.shared.drop_ip:set(ip,retry+1,lock_time)
		write_drop_ip2('inc',lock_time,rule,name)
		ngx.shared.btwaf_data:delete(ip)
	else
	    if name ~= 'cc' then 
	        totla_log_insert('log',server_name,ip,method,request_uri,ngx.var.http_user_agent,lan_type,rule,name,http_log(),'','')
	    end
	end
	write_to_file(logstr)
	if name ~= 'cc' then  
		inc_log(name,rule)
	end
end


local function write_drop_ip(is_drop,drop_time,name)
	local filename = cpath .. 'drop_ip.log'
	local fp = io.open(filename,'ab')
	if fp == nil then return false end
	if lan_type then lan_type=lan_type end 
	if is_type_rule then lan_type=is_type_rule end 
	if config['send_to'] and config['send_to'] ~='ERROR' then 
    	local logs_data={os.time(),"网站 "..server_name.." 遭到IP "..ip.." 的攻击".."URL为: "..request_uri}
    end
	local logtmp = {os.time(),ip,server_name,request_uri,drop_time,is_drop,method,ngx.var.http_user_agent,name,rule,http_log()}
	totla_log_insert('ip',server_name,ip,method,request_uri,ngx.var.http_user_agent,lan_type,name,'',http_log(),is_drop,drop_time)
	totla_log_insert('log',server_name,ip,method,request_uri,ngx.var.http_user_agent,lan_type,name,'',http_log(),'','')
	bt_ip_filter(ip,drop_time)
	logs(ip..drop_time)
	local logstr = json.encode(logtmp) .. "\n"
	fp:write(logstr)
	fp:flush()
	fp:close()
	inc_log(is_drop,rule)
	return true
end

function  return_error2(rule,rule2)
    is_type="http包非法"
	error_rule = 'from-data 请求异常,拒绝访问,如有误报请点击误报'..' >> '..rule..' >> '..rule2
	write_log('post','from-data 请求异常,拒绝访问,如有误报请点击误报')
    local check_html = [[<html><meta charset="utf-8" /><title>from-data请求error</title><div>宝塔WAF提醒您,from-data 请求异常,拒绝访问,如有误报请点击误报</div></html>]]
		ngx.header.content_type = "text/html;charset=utf8"
		ngx.header.Cache_Control = "no-cache"
		ngx.say(check_html)
		ngx.exit(200)
end 


local function is_ssl()
    if(ngx.re.match(request_uri,'^/.well-known/pki-validation/')) then return true end 
    if(ngx.re.match(request_uri,'^/.well-known/acme-challenge/')) then return true end    
end 

local function drop_abroad()
	if ip == 'unknown' then return false end
	if string.find(ip,':') then return false end
	if is_ssl() then return false end
	if ip=='91.199.212.132' or ip=='91.199.212.133' or ip=='91.199.212.148' or ip=='91.199.212.151' or ip=='91.199.212.176' then return false end
	if not config['drop_abroad']['open'] or not is_site_config('drop_abroad') then return false end	
	for _,v in ipairs(cnlist) do if compare_ip2(v) then return false end end
	ngx.exit(config['drop_abroad']['status'])
	return true
end

local  function is_ip_lan()
    for k,v in ipairs(lanlist) do if compare_ip2(v) then return true end  end
    return false
end

local function drop_china()
	if ip == 'unknown' then return false end
	if string.find(ip,':') then return false end
	if config['drop_china'] ==nil then return false end 
	if site_config[server_name] ==nil then return false end 
	if site_config[server_name]['drop_china'] ==nil then return false end 
	if is_ssl() then return false end
	if not config['drop_china']['open'] or not site_config[server_name]['drop_china'] then return false end
    if config['drop_china']['open'] and site_config[server_name]['drop_china'] then
    	if is_ip_lan() then return false end 
    	for k,v in ipairs(cnlist) do if compare_ip2(v) then 	ngx.exit(config['drop_china']['status']) end end
    	return false
    end
    return false
end


local function drop()
	local count,_ = ngx.shared.drop_ip:get(ip)
	if not count then return false end
	if count then
    	ngx.exit(config['cc']['status'])
    	return true
	elseif count ==30 then 
        bt_ip_filter(ip,3600)
        ngx.exit(config['cc']['status'])
		return true
    elseif count ==120 then 
        bt_ip_filter(ip,86400)
        ngx.exit(config['cc']['status'])
		return true
    end 
    return false
end

local function split2(input, delimiter)
    input = tostring(input)
    delimiter = tostring(delimiter)
    if (delimiter=='') then return false end
    local pos,arr = 0, {}
    for st,sp in function() return string.find(input, delimiter, pos, true) end do
        table.insert(arr, string.sub(input, pos, st - 1))
        pos = sp + 1
    end
    table.insert(arr, string.sub(input, pos))
    return arr
end

local function return_cc_url()
    if site_config[server_name]==nil then return request_uri end
    if site_config[server_name]['cc_type_status']==nil then return request_uri end
    cc_type_status=site_config[server_name]['cc_type_status']
    if cc_type_status ~=nil then 
        if cc_type_status==1 then 
            return request_uri
        elseif  cc_type_status==2 then 
            -- url_data=split2(request_uri,'?')
            if not url_data then url_data=request_uri end 
            if not url_data[1] then 
                url_data=request_uri 
            else
                url_data=url_data[1]
            end
            return url_data
        elseif  cc_type_status==3 then 
            return ip
        elseif  cc_type_status==4 then 
            return ip..request_header['user-agent']
        end
    end 
    return request_uri
end

local function cc()
	if not config['cc']['open'] or not site_cc then return false end
	local token = ngx.md5(ip .. '_' .. return_cc_url())
	local token2 = ngx.md5(ip .. '_' ..'return_cc_url')
	local count,_ = ngx.shared.btwaf:get(token)
	local count2,_ = ngx.shared.btwaf:get(token2)
	if count and not count2 then 
	    ngx.shared.btwaf:delete(token)
	    count=0
	end
	if count and count2 then
		if count > limit then
		    
			local safe_count,_ = ngx.shared.drop_sum:get(ip)
			if not safe_count then
				ngx.shared.drop_sum:set(ip,1,86400)
				safe_count = 1
			else
				ngx.shared.drop_sum:incr(ip,1)
			end
			local lock_time = (endtime * safe_count)
			if lock_time > 86400 then lock_time = 86400 end
			ngx.shared.drop_ip:set(ip,retry+1,lock_time)
			bt_ip_filter(ip,lock_time)
			is_type='cc'
			write_log('cc',cycle..'秒内累计超过'..limit..'次请求,封锁' .. lock_time .. '秒')
			write_drop_ip('cc',lock_time,cycle..'秒内累计超过'..limit..'次请求,封锁' .. lock_time .. '秒')
			ngx.exit(config['cc']['status'])
			return true
		else
			ngx.shared.btwaf:incr(token,1)
			ngx.shared.btwaf:incr(token2,1)

		end
	else
		ngx.shared.btwaf:set(token,1,cycle)
		ngx.shared.btwaf:set(token2,1,cycle)
	end
	return false
end


local function send_check_heml(cache_token)
	local check_key = tostring(math.random(1000,99999999))
	ngx.shared.btwaf:set(cache_token .. '_key',check_key,60)
	local vargs = '&btwaf='
	local sargs = string.gsub(request_uri,'.?btwaf=.*','')
	if not string.find(sargs,'?',1,true) then vargs = '?btwaf=' end
	local safe_count = ngx.shared.drop_sum:get(ip..today)
	if not safe_count then
		ngx.shared.drop_sum:set(ip..today,1,endtime)
		safe_count = 1
	else
		ngx.shared.drop_sum:incr(ip..today,1)
		safe_count = safe_count +1
	end
	if safe_count >= retry then
		local safe_count2,_ = ngx.shared.drop_sum:get(ip)
		if not safe_count2 then safe_count2=1 end
		retry_time = site_config[server_name]['retry_time']
		local lock_time = (retry_time * safe_count2)
		if lock_time > 86400 then lock_time = 86400 end
		is_type='cc'
		write_log('cc','累计超过'.. retry ..'次验证失败,封锁' .. lock_time .. '秒')
		write_drop_ip('cc',lock_time,'累计超过'.. retry ..'次验证失败,封锁' .. lock_time .. '秒')
	end
	local check_html = [[<html><meta charset="utf-8" /><title>检测中</title><div>跳转中</div></html>
<script> window.location.href ="]] .. sargs .. vargs .. check_key .. [["; </script>]]
	ngx.header.content_type = "text/html;charset=utf8"
	
	local token=''
    if request_header['user-agent']~=nil then 
    	token=ngx.md5(ip..request_header['user-agent']..server_name..'btwaf'..today)
    else
    	token=ngx.md5(ip..server_name..type..today)
    end 
-- 	token=ngx.md5(ip..request_header['user-agent']..server_name..'btwaf')
    jwt_value=ngx.md5(os.time()..ip)
    ngx.status = 403
    ngx.shared.btwaf:set(token,jwt_value,7200)
    ngx.header.Set_Cookie =token.."="..jwt_value..';'
	ngx.header.Cache_Control = "no-cache"
	ngx.say(check_html)
	ngx.exit(403)
end

local function security_verification()
	if  not uri_request_args['btwaf'] then return false end
	local cache_token = ngx.md5(ip .. '_' .. server_name)
	check_key = ngx.shared.btwaf:get(cache_token .. '_key')
	if check_key == uri_request_args['btwaf'] then
		return true
	end
	return false
end

local function scan_black()
	if not config['scan']['open'] or not is_site_config('scan') then return false end
	if is_ngx_match(scan_black_rules['cookie'],request_header['cookie'],false) then
		write_log('scan','扫描器拦截')
		ngx.exit(config['scan']['status'])
		return true
	end
	if is_ngx_match(scan_black_rules['args'],request_uri,false) then
		write_log('scan','扫描器拦截')
		ngx.exit(config['scan']['status'])
		return true
	end
	for key,value in pairs(request_header)
	do
		if is_ngx_match(scan_black_rules['header'],key,false) then
			write_log('scan','扫描器拦截')
			ngx.exit(config['scan']['status'])
			return true
		end
	end
	return false
end

local function ip_black()
    if arrlen(ip_black_rules)==0 then return false end 
	for _,rule in ipairs(ip_black_rules)
	do
		if compare_ip2(rule) then 
		lan_ip('args','ip黑名单')
		ngx.exit(config['cc']['status'])
		return true end
	end
	return false
end

function ip_white()
    if count_sieze(ip_white_rules)==0 then return false end 
	if ngx.var.server_name =='_' and ip =='127.0.0.1' then return false end
	for _,rule in ipairs(ip_white_rules) do	if compare_ip2(rule) then return true end end
	return false
end

local function url_white()
	if ngx.var.document_root=='/www/server/phpmyadmin' then return true end
	if count_sieze(url_white_rules)==0 then return false end 
	if is_ngx_match(url_white_rules,request_uri,false) then
        if not url_data then url_data=request_uri end 
        if not url_data[1] then 
            url_data=request_uri 
        else
            url_data=url_data[1]
        end
        if ngx.re.match(url_data,'/\\.\\./') then return false end
		return true
	end
	return false
end

local function url_black()
    if arrlen(url_black_rules)==0 then return false end 
	if is_ngx_match(url_black_rules,request_uri,false) then	ngx.exit(config['get']['status']) return true end
	return false
end

local function user_agent()
	if not config['user-agent']['open'] or not is_site_config('user-agent') then return false end	
	if is_ngx_match(user_agent_rules,request_header['user-agent'],'user_agent') then lan_ip('user_agent','UA存在问题已经被系统拦截。并封锁IP') return true end
	return false
end

local function de_dict (l_key,l_data)
	if type(l_data) ~= "table" then return l_data end
	if arrlen(l_data) == 0 then return l_data end
	if not l_data then return false end
	local r_data = {}
	if arrlen(l_data) >= 5000 then 
	    is_type='POST参数'
		lan_ip('args','非法请求')
		return true
	end
	for li,lv in pairs(l_data)
	do
		r_data[l_key..tostring(li)] = lv
	end
	return r_data
end

local function _process_json_args(json_args,t)
		if type(json_args)~='table' then return {} end
        local t = t or {}
        for k,v in pairs(json_args) do
                if type(v) == 'table' then
            for _k,_v in pairs(v) do
                    if type(_v) == "table" then
                        t = _process_json_args(_v,t)

                    else
                            if type(t[k]) == "table" then
                                    table.insert(t[k],_v)

                            elseif type(t[k]) == "string" then
                                    local tmp = {}
                                    table.insert(tmp,t[k])
                                    table.insert(tmp,_v)
                                    t[k] = tmp
                            else

                            t[k] = _v
                            end
                    end

            end
                else
                     if type(t[k]) == "table" then
                            table.insert(t[k],v)
                    elseif type(t[k]) == "string" then
                            local tmp = {}
                            table.insert(tmp,t[k])
                            table.insert(tmp,v)
                            t[k] = tmp
                    else

                    t[k] = v
                    end
                end
        end
        return t
end

local function ReadFileHelper4(str)
	 if type(str)~='string' then return str end
	 res = string.gsub(str, "@", "")
    return res
end

local function libinjection_chekc(requires_data)
	if type(requires_data)~='table' then return false end 
	for k,v in pairs(requires_data) do
		if continue_key(k) then
			if type(v)=='string' then
				is_body_intercept(v)
			 	if config['post_is_sql']  and is_site_config('post_is_sql') then 
					local issqli, fingerprint = libinjection.sqli(tostring(ReadFileHelper4(v)))
					local issqli2, fingerprint = libinjection.sqli(tostring(ReadFileHelper4(k)))
					if issqli or issqli2 then
						error_rule = '语义分析分析出sql注入' .. ' >> ' .. tostring(k)..'='..tostring(v)..' >> '..tostring(v)
						is_type='SQL注入'
						return true 
					end 
				end 
				if config['post_is_xss'] then
					local isxss = libinjection.xss(tostring(v))
					if isxss then
						if not ngx.shared.btwaf_data:get(ip..'xss') then 
							ngx.shared.btwaf_data:set(ip..'xss',1,360)
						else
							ngx.shared.btwaf_data:incr(ip..'xss',1)
						end
						if config['post_is_xss_count'] ~=nil then 
						    post_is_xss_count=config['post_is_xss_count'] 
						else
						    post_is_xss_count=6
						end
						if ngx.shared.btwaf_data:get(ip..'xss')>=post_is_xss_count then
							error_rule = '语义分析分析出xss跨站攻击' .. ' >> ' .. tostring(k)..'='..tostring(v)..' >> '..tostring(v)
							is_type="XSS攻击"
							return true
						end
					end
				end
			end
		else
			if type(v)=='string' then
				is_body_intercept(v)
			end
		end
	end 
	return false
end


function is_ngx_match_urlencoded(rules,sbody,rule_name,disable,threshold)
	if rules == nil or sbody == nil then return false end
	if type(sbody) == "string" then
		sbody = {sbody}
	end
	if type(rules) == "string" then
		rules = {rules}
	end
	local count=0
	local fix=0
	for k,body in pairs(sbody)
    do  
		if continue_key(k)  then
			for i,rule in ipairs(rules)
			do
				if site_config[server_name] and rule_name then
					local n = i - 1
					for _,j in ipairs(site_config[server_name]['disable_rule'][rule_name])
					do
						if n == j then
							rule = ""
						end
					end
				end
				for _,num in pairs(disable) do
					if num == i or i > threshold then 
						if body and rule ~="" then
						
							if k and rule ~="" then
								if type(k) == "string" and type(rule)=='string' then
									if ngx_match(ngx.unescape_uri(k),rule,"isjo") then
										is_type=is_type_return(rule_name,rule,"static")
										error_rule = rule .. ' >> ' .. k.. ' >> ' .. k
										ngx.shared.btwaf_data:incr(ip,100)
										count=count+1
										fix=fix+100
									end
								elseif  type(k) == "string" and type(rule)=='table' then
									if ngx_match(ngx.unescape_uri(k),rule[1],"isjo") then
										is_type=is_type_return(rule_name,rule[2],"ip")
										error_rule = rule[1] .. ' >> ' .. k.. ' >> ' .. k
										ngx.shared.btwaf_data:incr(ip,rule[3])
										count=count+1
										fix=fix+rule[3]
									end
								end
							end
						
							if type(body) == "string" and type(rule)=='string' then
								if ngx_match(ngx.unescape_uri(body),rule,"isjo") then
									if method ~="POST" and  rule=="'$" then
									    return false
									end
									is_type=is_type_return(rule_name,rule,"static")
									error_rule = rule .. ' >> ' .. k .. '=' .. body ..' >> ' .. body
									ngx.shared.btwaf_data:incr(ip,100)
									count=count+1
									fix=fix+100
								end 
							elseif type(body) == "string" and type(rule)=='table' then
								    if ngx_match(ngx.unescape_uri(body),rule[1],"isjo") then
    									if method ~="POST" and  rule=="'$" then
    									    ngx.shared.btwaf_data:incr(ip,100)
    									    count=count+1
									        fix=fix+100
    									end
    									is_type=is_type_return(rule_name,rule[2],"static")
    									error_rule = rule[1] .. ' >> ' .. k .. '=' .. body ..' >> ' .. body
    									ngx.shared.btwaf_data:incr(ip,rule[3])
    									count=count+1
									    fix=fix+rule[3]
    								end 
								end
							end
						end
					end
				end
			end
		end
	if count >=2 then return true end 
	if fix>=100 then  return true end 
	return false
end


local function post_urlencoded(request_args)
	if ngx.shared.btwaf_data:get(ip..'post') then 
		disable={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25}
	else
		disable={1,2,3,4,5,6,7,8,9,12,13,21,23,24,25}
	end 
	 if is_ngx_match_urlencoded(post_rules,request_args,'post',disable,25) then 
	    write_log('post','POST拦截1')
	    return_html(config['post']['status'],post_html)
	 end 
	 if ngx.shared.btwaf_data:get(ip) >1000 then 
	    lan_ip('post','ip攻击次数多被拦截111')
	 end
	if libinjection_chekc(request_args) then
	    ngx.shared.btwaf_data:incr(ip,100)
		ngx.shared.btwaf_data:set(ip..'post','1',360)
		write_log('post','POST语义分析拦截')
		return_html(config['post']['status'],post_html)
	end

end


local function post()
	if not config['post']['open'] or not is_site_config('post') then return false end	
	if method == "GET" then return false end
	content_length=tonumber(request_header['content-length'])
	if content_length == nil then return false end
	local content_type = ngx.req.get_headers(20000)["content-type"]
	if not content_type then return false end 
	if type(content_type)~='string' then 
		return_error(17)
	end 
	if content_type and ngx.re.find(content_type, 'multipart',"oij") then return false end 
	ngx.req.read_body()
	request_args = ngx.req.get_post_args(1000000)
	if not request_args then
		if content_length >10000 then 
		  --  request_uri22=split2(request_uri,'?')
		    request_uri22=url_data[1]
			local check_html = [[<html><meta charset="utf-8" /><title>Nginx缓冲区溢出</title><div>宝塔WAF提醒您,Nginx缓冲区溢出,传递的参数超过接受参数的大小,出现异常,<br>第一种解决方案:把当前url-->]]..'^'..request_uri22..[[加入到URL白名单中,如有疑问请联系官方运维QQ</br>第二种解决方案:面板-->nginx管理->性能调整-->client_body_buffer_size的值调整为10240K 或者5024K(PS:可能会一直请求失败建议加入白名单)</br></div></html>]]
			ngx.header.content_type = "text/html;charset=utf8"
			ngx.header.Cache_Control = "no-cache"
			ngx.say(check_html)
			ngx.exit(200)
		end 
		return true
	end
	if count_sieze(request_args)==0 then return false end 
	list_data={}
	if type(request_args)=='table' then
		for k,v in pairs(request_args)
		do
			if type(v)=='table' then
				table.insert(list_data,de_dict(k,v))
			end
            if type(v)=='string' then
				if not  string.find(v,'^data:.+/.+;base64,') then
					if (#v) >=400000 then
						write_log('post',k..'     参数值长度超过40w已被系统拦截')
						return_html(config['post']['status'],post_html)
						return true
					end
				else
					kkkkk=ngx.re.match(v,'^data:.+;base64,','ijo')
					if  kkkkk then 
						if kkkkk[0] then 
							if ngx.re.match(kkkkk[0],'php') or ngx.re.match(kkkkk[0],'jsp') then 
							    is_type='webshell防御'
								write_log('post','拦截Bae64上传php文件')
								return_html(config['post']['status'],post_html)
							end 
						end
					end
				end
			end
		end
	end
	if content_type and  ngx.re.find(content_type, '^application/json',"oij") and ngx.req.get_headers(20000)["content-length"] and tonumber(ngx.req.get_headers(20000)["content-length"]) ~= 0 then
		local ok ,request_args = pcall(function()
			return json.decode(ngx.req.get_body_data())
		end)
		if not ok then
			local check_html = [[<html><meta charset="utf-8" /><title>json格式错误</title><div>请传递正确的json参数</div></html>]]
			ngx.header.content_type = "text/html;charset=utf8"
			ngx.header.Cache_Control = "no-cache"
			ngx.say(check_html)
			ngx.exit(200)
		end
		if type(request_args)~='table' then return false end 
		request_args=_process_json_args(request_args)
		return post_urlencoded(request_args)
	else
		if list_data then 
			if arrlen(list_data)>=1 then 
				for i2,v2 in ipairs(list_data) do 
					post_urlencoded(v2)
					request_args=_process_json_args(v2,request_args)
				end 
			else 
				request_args=_process_json_args(list_data,request_args)
			end 
		else
			request_args =_process_json_args(request_args)
		end
		if count_sieze(request_args)>=3000 then
		    is_type='POST参数'
			error_rule = '参数太多POST传递的参数数量超过800,拒绝访问,如有误报请点击误报'
		    write_log('post','参数太多POST传递的参数数量超过800,拒绝访问,如有误报请点击误报')
		    return_html_data('网站防火墙','您的请求带有不合法参数，已被网站管理员设置拦截','网站防火墙提醒您POST传递的参数数量超过800,拒绝访问','点击误报')
		end
	    post_urlencoded(request_args)
	end
	return false
end

function lan_ip(type,name)
	local safe_count,_ = ngx.shared.drop_sum:get(ip)
	if not safe_count then
		ngx.shared.drop_sum:set(ip,1,86400)
		safe_count = 1
	else
		ngx.shared.drop_sum:incr(ip,1)
	end
	local lock_time = (endtime * safe_count)
	if lock_time > 86400 then lock_time = 86400 end
	ngx.shared.drop_ip:set(ip,retry+1,lock_time)
	local method = ngx.req.get_method()
	if error_rule then 
		rule = error_rule
		error_rule = nil
	end
	if is_type then 
		is_type_rule = is_type
		is_type = nil
	end
	local logtmp = {ngx.localtime(),ip,method,request_uri,ngx.var.http_user_agent,type,name,http_log(),is_type_rule}
	local logstr = json.encode(logtmp) .. "\n"
	write_to_file(logstr)
	inc_log(type,rule)
	if type =='args' or type=='post' or type =='inc' then 
		write_drop_ip2('inc',lock_time,name,rule)
	else
		write_drop_ip2(type,lock_time,name,rule)
	end 
	ngx.exit(config['cc']['status'])
end

local function disable_upload_ext(ext)
	if not ext then return false end
	if type(ext)=='string' then 
		ext = string.lower(ext)
		if ngx.re.match(ext,'.user.ini') or ngx.re.match(ext,'.htaccess') or ngx.re.match(ext,'php') or ngx.re.match(ext,'jsp') then 
		    is_type='webshell防御'
	        lan_ip('disable_upload_ext','上传非法文件被系统拦截,并且被封锁IP')
		    return true
		end
	end 
	if not site_config[server_name] then return false end 
	disa=site_config[server_name]['disable_upload_ext']
	ret={}
	for _,k  in ipairs(disa) 
	do 
		if k~='so' then 
			table.insert(ret,k)
		end
	end
	if is_ngx_match(ret,ext,'post') then
	    is_type='webshell防御'
		lan_ip('disable_upload_ext','上传非法PHP文件被系统拦截,并且被封锁IP2'..' >> '..ext)
		return true
	end
end

local function return_error(int_age)
    is_type='http包非法'
	lan_ip('post','http包非法,并且被封锁IP,如果自定义了from-data可能会导致误报。如果大量出现当前问题。请在全局设置中关闭from_data协议规范'..int_age)
end 

local function disable_upload_ext2(ext)
	if not ext then return false end
    if type(ext)~='table' then return false end 
	for i,k in pairs(ext) do 
	    for i2,k2 in pairs(k) do
	       check_file=ngx.re.gmatch(k2,[[filename=]],'ijo')
	       ret={}
	       while true do
    		    local m, err = check_file()
    	      	if m then 
    	      		table.insert(ret,m)
    	      	else
    	      		break
    	      	end 
	       end
            if arrlen(ret)>1 then 
                return_error(1)
            end
    	    if not ngx.re.match(k2,[[filename=""]],'ijo') and  not ngx.re.match(k2,[[filename=".+"]],'ijo') then 
				return_error(2)
    	    else 
    	        k2 = string.lower(k2)
    	        if site_config[server_name] ==nil then return false end 
	        	disa=site_config[server_name]['disable_upload_ext']
            	if is_ngx_match(disa,k2,'post') then
            	    is_type='恶意上传'
            		lan_ip('disable_upload_ext','上传非法PHP文件被系统拦截,并且被封锁IP3'..' >> '..k2)
            		return true
            	end
    	    end
		
    	 end 
	end 
	
end

local function  from_data(data,data2,data3)
	if arrlen(data) ==0 then return false end 
	local count=0
	for k,v in pairs(data) do
	    if ngx.re.match(v[0],'filename=') then 
	        if not ngx.re.match(v[0],'Content-Disposition: form-data; name="[^"]+"; filename=""\r*$','ijo') then 
	            if not ngx.re.match(v[0],'Content-Disposition: form-data; name="[^"]+"; filename="[^"]+"\r*$','ijo') then 
	                is_type='恶意上传'
	                return_error2(v[0],'4.5')
	            end
	        end
	        count=count+1
	        disable_upload_ext(v[0])
	    end
	    if config['from_data'] then 
			if not ngx.re.match(v[0],'filename=') and  not ngx.re.match(v[0],'Content-Disposition: form-data; name="[^"]+"\r*$','ijo')  then 
			    is_type='http包非法'
				if not ngx.re.match(v[0],[[Content-Disposition: form-data; name=""]],'ijo') then 
					return_error2(v[0],'5')
				end
			end
		end
	end
    len_count=arrlen(data2)+arrlen(data3)
	if count ~=len_count then
		   is_type='http包非法'
	       return_error2('','6')
	 end 
end


local function disable_upload_ext3(ext,check)
	if not ext then return false end
    if type(ext)~='table' then return false end 
    for i2,k2 in pairs(ext) do
        check_file=ngx.re.gmatch(k2,[[ filename=]],'ijo')
       ret={}
      while true do
    	    local m, err = check_file()
          	if m then 
          		table.insert(ret,m)
          	else
          		break
          	end 
       end
        if arrlen(ret)>1 then 
            return_error(6)
        end
        if check==1 then
             if arrlen(ret)==0 then 
            	if not k2 then return false end 
				kkkkk=ngx.re.match(k2,[[Content-Disposition:.{200}]],'ijo')
			    if not kkkkk then 
                	if not ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"\r\r]],'ijom') or ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"\r\r;name=]],'ijo')  or ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"\r\r;\s*\r*\n*n\s*\r*\n*a\s*\r*\n*m\s*\r*\n*e\s*\r*\n*=]],'ijo') or ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"\r\s*;]],'ijo') then 
                		k2=string.gsub(k2,'\r','')
                		if ngx.re.match(k2,[[filename=]],'ijo') then 
                		    is_type='恶意上传'
                		    return lan_ip('disable_upload_ext','非法上传请求已被系统拦截,并且被封锁IP1') 
                		end 
						if not ngx.re.match(k2,[[Content-Disposition: form-data; name=""]],'ijo') and not  ngx.re.match(k2,'^Content-Disposition: form-data; name=".+"','ijo') then 
							return return_error2('','1')
						end
                	end
                else
                    k2=kkkkk[0]
                    if not ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"\r\r]],'ijom') or ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"\r\r;name=]],'ijo')  or ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"\r\r;\s*\r*\n*n\s*\r*\n*a\s*\r*\n*m\s*\r*\n*e\s*\r*\n*=]],'ijo') or ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"\r\s*;]],'ijo') then 
                		k2=string.gsub(k2,'\r','')
                		if ngx.re.match(k2,[[filename=]],'ijo') then 
                		    is_type='恶意上传'
                		    return lan_ip('disable_upload_ext','非法上传请求已被系统拦截,并且被封锁IP2') 
                		end
                		return return_error2('','2')
                	end
                end
                if k2 then 
                	k2=string.gsub(k2,'\r','')
            		if ngx.re.match(k2,[[filename=]],'ijo') then 
            		    is_type='恶意上传'
            		    return lan_ip('disable_upload_ext','非法上传请求已被系统拦截,并且被封锁IP3') 
            	    end 
                end
            	if ngx.re.match(k2,[[Content-Disposition: form-data; name="(.+)"\r]],'ijos') then 
            	    tttt=ngx.re.match(k2,[[Content-Disposition: form-data; name="(.+)"\r\s]],'ijos')
                    if tttt==nil then return false end 
                    if #tttt[0] >200 then return false end
                    if tttt[1] ==nil then return false end 
                    tttt[1]=string.gsub(tttt[1],'\n','')
		            tttt[1]=string.gsub(tttt[1],'\t','')
		            tttt[1]=string.gsub(tttt[1],'\r','')
		            if ngx.re.match(tttt[1],'name=','ijo') then return return_error2(tttt[1],tttt[1]) end
            	end
            	if ngx.re.match(k2,[[\r\r(.+)\r\r]],'ijos') then 
            	    tttt=ngx.re.match(k2,[[\r\r(.+)\r\r]],'ijos')
                    if tttt==nil then return false end 
                    if #tttt[0] >200 then return false end 
                    if tttt[1] ==nil then return false end 
                    tttt[1]=string.gsub(tttt[1],'\n','')
		            tttt[1]=string.gsub(tttt[1],'\t','')
		            tttt[1]=string.gsub(tttt[1],'\r','')
		            if ngx.re.match(tttt[1],'name=','ijo') then return return_error2(tttt[1],tttt[1]) end
            	end
			else
				if not k2 then return false end 
				k2=string.gsub(k2,'\r','')
				kkkkk=ngx.re.match(k2,[[Content-Disposition:.{200}]],'ijo')
				if not kkkkk then 
				    k3=ngx.re.match(k2,[[Content-Disposition:.+Content-Type:]],'ijo')
				    is_type='恶意上传'
				    if not k3 then return lan_ip('disable_upload_ext','非法上传请求已被系统拦截,并且被封锁IP4') end 
				    
				    if not ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"; filename=""Content-Type:]],'ijo') and not  ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"; filename=".+"Content-Type:]],'ijo') then 
				        is_type='恶意上传'
            	        return lan_ip('disable_upload_ext','非法上传请求已被系统拦截,并且被封锁IP5')
            	    end 
				else
				    k3=ngx.re.match(kkkkk[0],[[Content-Disposition:.+Content-Type:]],'ijo')
				    if not k3 then 
				        return false
				        end 
					if not ngx.re.match(k3[0],[[Content-Disposition: form-data; name=".+"; filename=""Content-Type:]],'ijo') and not  ngx.re.match(k3[0],[[Content-Disposition: form-data; name=".+"; filename=".+"Content-Type:]],'ijo') then
					    is_type='恶意上传'
            	        return lan_ip('disable_upload_ext','非法上传请求已被系统拦截,并且被封锁IP7')
            	    end
				end
				if site_config[server_name] ==nil then return false end 
            	disa=site_config[server_name]['disable_upload_ext']
            	if is_ngx_match(disa,k3,'post') then
            	    is_type='恶意上传'
            		lan_ip('disable_upload_ext','上传非法PHP文件被系统拦截,并且被封锁IP4')
            	end
            	if #k3[0] >200 then 
        	       ret10={}
            	   local tmp10 = ngx.re.gmatch(k3[0],'form-data')
            	   while true do local m, err = tmp10() if m then  table.insert(ret10,m) else break end  end
                   if tonumber(arrlen(ret10)) >1 then return false end 
                   if ngx.re.match(k3[0],'--$') then return false end
                   return return_message(200,'error1->The upload file name is too long')
        	   	end
            	local tmp8 = ngx.re.gmatch(k3[0],'\"')
            	local tmp9 = ngx.re.gmatch(k3[0],'=')
            	local tmp10 = ngx.re.gmatch(k3[0],';')
                ret8={}
                ret9={}
                ret10={}
                while true do local m, err = tmp8() if m then  table.insert(ret8,m) else break end  end
                while true do local m, err = tmp9() if m then  table.insert(ret9,m) else break end  end
                while true do local m, err = tmp10() if m then  table.insert(ret10,m) else break end  end
                if tonumber(arrlen(ret9))~=2 and tonumber(arrlen(ret8))~=4 and tonumber(arrlen(ret10))~=2 then
                    return_error2('','10')
                end
             end
            
        else 
            if arrlen(ret)==0 then
                return false
            else 
                kkkkk=ngx.re.match(k2,[[Content-Disposition:.{200}]],'ijo')
				if not kkkkk then 
				    k3=ngx.re.match(k2,[[Content-Disposition:.+Content-Type:]],'ijo')
				    if not k3 then return return_error(7) end 
				    if not ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"; filename=""Content-Type:]],'ijo') and not  ngx.re.match(k2,[[Content-Disposition: form-data; name=".+"; filename=".+"Content-Type:]],'ijo') then 
				        is_type='恶意上传'
            	        return lan_ip('disable_upload_ext','非法上传请求已被系统拦截,并且被封锁IP5')
            	    end 
				else
				    k3=ngx.re.match(kkkkk[0],[[Content-Disposition:.+Content-Type:]])
				    if not k3 then 
				        return false
				    end 
					if not ngx.re.match(k3[0],[[Content-Disposition: form-data; name=".+"; filename=""Content-Type:]],'ijo') and not  ngx.re.match(k3[0],[[Content-Disposition: form-data; name=".+"; filename=".+"Content-Type:]],'ijo') then
					     is_type='恶意上传'
            	        return lan_ip('disable_upload_ext','非法上传请求已被系统拦截,并且被封锁IP7')
            	    end
				end
				k3=k3[0]
        	    if not ngx.re.match(k3,[[filename=""Content-Type]],'ijo') and  not ngx.re.match(k3,[[filename=".+"Content-Type]],'ijo') then 
        			return_error(8)
        	    else
        	    	check_filename=ngx.re.match(k3,[[filename="(.+)"Content-Type]],'ijo')
        	        if check_filename then 
        	            if check_filename[1] then
        	                if ngx.re.match(check_filename[1],'name=','ijo') then return return_error(9) end 
        	                if ngx.re.match(check_filename[1],'php','ijo') then return return_error(10) end 
        	                if ngx.re.match(check_filename[1],'jsp','ijo') then return return_error(11) end 
        	            end 
        	        end
        	        if #k3 >=200 then 
        	           is_type='文件名过长'
                       write_log('post','上传的文件名太长了,被系统拦截')
                       return return_message(200,k3)
        	        end
        	        k3 = string.lower(k3)
        	        if site_config[server_name] ==nil then return false end 
                	disa=site_config[server_name]['disable_upload_ext']
                	if is_ngx_match(disa,k3,'post') then
                	    is_type='恶意上传'
                		lan_ip('disable_upload_ext','上传非法PHP文件被系统拦截,并且被封锁IP1'..' >> '..k3)
                		return true
                	end
        	    end
            end 
        end 
	 end
end

local function post_data()
	if not config['post']['open'] or not is_site_config('post') then return false end
	if method ~= "POST" then return false end
	content_length=tonumber(request_header['content-length'])
	if not content_length then return false end
	if content_length >108246867 then return false end 
	local boundary = get_boundary()
	if boundary then
		ngx.req.read_body()
		local data = ngx.req.get_body_data()
		if not data then 
		   data=ngx.req.get_body_file()
		   if data==nil then return false end 
            data=read_file_body(data) 
		end
		if not data then return false end
		data233=string.gsub(data,'\r','')
		local tmp4 = ngx.re.gmatch(data,[[Content-Disposition.+]],'ijo')
		local tmp5 = ngx.re.gmatch(data,[[Content-Disposition: form-data; name=".+"; filename=".+"\r\nContent-Type:]],'ijo')
		local tmp6 = ngx.re.gmatch(data,[[Content-Disposition: form-data; name=".+"; filename=""\r\nContent-Type:]],'ijo')
		ret3={}
		while true do local m, err = tmp4() if m then table.insert(ret3,m) else break end  end
		ret5={}
		while true do local m, err = tmp5() if m then  table.insert(ret5,m) else break end end
	    ret6={}
		while true do  local m, err = tmp6() if m then  table.insert(ret6,m) else break end  end
		from_data(ret3,ret5,ret6)
		local tmp2 = ngx.re.gmatch(data,[[Content-Disposition.+filename=.+]],'ijo')
		local tmp3 = ngx.re.gmatch(data,[[Content-Disposition.+\s*f\r*\n*o\r*\n*r\r*\n*m\r*\n*-\r*\n*d\r*\n*a\r*\n*t\r*\n*a\r*\n*\s*;\r*\n*\s*n\r*\n*a\r*\n*m\r*\n*e=\r*\n*.+;\s*f\n*\s*\r*i\n*\s*\r*l\n*\s*\r*e\n*\s*\r*n\n*\s*\r*a\n*\s*\r*m\n*\s*\r*e\n*\s*\r*=.+\n*\s*\r*]],'ijo')
		ret={}
		while true do local m, err = tmp2() if m then  table.insert(ret,m) else break end  end
		ret2={}
		while true do local m, err = tmp3() if m then  table.insert(ret2,m) else break end  end
		disable_upload_ext2(ret2)
	    if arrlen(ret)==0 and arrlen(ret2)>0 then 
	        return_error(3)
	    end
	    ret=gusb_string(ret)
		for k,v in pairs(ret) do 
			disable_upload_ext(v)
		end
		local tmp2=ngx.re.match(data,[[Content-Type:[^\+]{100}]],'ijo')
		if tmp2 and tmp2[0] then 
			data_in_php(tmp2[0])
		end
		av=ngx.re.match(boundary,"=.+")
		if not av then 
			write_log('post','content_type_null')
			return_html(config['post']['status'],post_html)
		end
		header_data=ngx.re.gsub(av[0],'=','')
		if #header_data>200 then 
		    return_error(5)
		end
	    data=string.gsub(data,'\n','')
		data=string.gsub(data,'\t','')
		local tmp_pyload2 = ngx.re.match(data,'Content-Disposition:.+\r--','ijo')
 		if tmp_pyload2==nil then return false end 
 		tmpe_data2=split2(tmp_pyload2[0],header_data)
		if arrlen(tmpe_data2)>0 then
			if config['from_data'] then 
	    		disable_upload_ext3(tmpe_data2,1)
	    	end
		end
		data=string.gsub(data,'\r','')
		local tmp_pyload = ngx.re.match(data,'Content-Disposition:.+Content-Type:','ijo')
         if tmp_pyload==nil then return false end 
		tmpe_data=split2(tmp_pyload[0],header_data)
		if arrlen(tmpe_data)>0 then 
		    disable_upload_ext3(tmpe_data,2)
		end 
	end
	return false
end


local function return_post_data2()
	if method ~= "POST" then return false end
	content_length=tonumber(request_header['content-length'])
	if not content_length then return false end
	local boundary = get_boundary()
	if boundary then
		ngx.req.read_body()
		local data = ngx.req.get_body_data()
		if not data then 
		   data=ngx.req.get_body_file()
			if data==nil then return false end
            data=read_file_body(data) 
		end
		if not data then return false end
		local tmp2 = ngx.re.gmatch(data,[[Content-Disposition.+filename=]],'ijo')
		ret={}
		while true do
		    local m, err = tmp2()
	      	if m then 
	      		table.insert(ret,m)
	      	else
	      		break
	      	end 
	    end
	    ret=gusb_string(ret)
	    if arrlen(ret)>=1 then  
		    for _,v in pairs(ret) do 
				if not ngx.re.match(v[0],'ContentbaotaDisposition: formbaotadata; name=".+"; filename=','ijo') and not ngx.re.match(v[0],'ContentbaotaDisposition: formbaotadata; name=”.+”; filename=','ijo') then 
					return_error(12)
				end
		    end
	    end
	    if arrlen(ret)==1 then 
	    	return 1 
	    else
	    	return 2 
	    end
	end
	return 3
end



local function cookie()
	if not config['cookie']['open'] or not is_site_config('cookie') then return false end
	if not request_header['cookie'] then return false end
	if type(request_header['cookie']) ~= "string" then return return_message(200,'Cookie ERROR') end
	if request_header['user-agent'] ==nil then return false end
    if type(request_header['user-agent']) ~= "string" then return false end
	request_cookie = string.lower(request_header['cookie'])
	if is_ngx_match(cookie_rules,request_cookie,'cookie') then
		write_log('cookie','cookie拦截')
		return_html(config['get']['status'],get_html)
		return true
	end
	return false
end

local function de_dict2(l_key,l_data)
	if type(l_data) ~= "table" then return l_data end
	if arrlen(l_data) == 0 then return l_data end
	if not l_data then return false end
	local r_data = {}
	if arrlen(l_data) >= 5000 then 
	    is_type='GET参数'
		lan_ip('args','非法请求')
		return true
	end
	for li,lv in pairs(l_data)
	do
		r_data[l_key..tostring(li)] = lv
	end
	return r_data
end




local function libinjection_args(requires_data)
	if type(requires_data)~='table' then return false end 
	for k,v in pairs(requires_data) do
		if type(v)=='string' then
			is_body_intercept(v)
		    if config['get_is_sql'] and  is_site_config('get_is_sql') then 
    			local issqli, fingerprint = libinjection.sqli(tostring(ReadFileHelper4(v)))
    			if issqli then 
    			    is_type='SQL注入'
    				error_rule = '语义分析分析出sql注入' .. ' >> ' .. tostring(k)..'='..tostring(v)
    				return true 
    			end
    		end
    		if config['get_is_xss']  then 
    			local isxss = libinjection.xss(tostring(v))
    			if isxss then 
    			    is_type='XSS防御'
    				error_rule = '语义分析分析出xss跨站攻击' .. ' >> ' ..tostring(k)..'='..tostring(v)
    				return true 
    			end
    		end
		end
	end 
	return false
end

local function is_ngx_match2(rules,sbody,rule_name)
	if rules == nil or sbody == nil then return false end
	if type(sbody) == "string" then
		sbody = {sbody}
	end
	
	local count =0
	local fraction=0
	if type(rules) == "string" then
		rules = {rules}
	end
	for k,body in pairs(sbody)
    do  
        
		if continue_key(k) then
			for i,rule in ipairs(rules)
			do
				if site_config[server_name] and rule_name then
					local n = i - 1
					for _,j in ipairs(site_config[server_name]['disable_rule'][rule_name])
					do
						if n == j then
							local rule = ""
						end
					end
				end
				if body and rule ~="" then
					if type(body) == "string" and type(rule) == "string" then
						if ngx_match(ngx.unescape_uri(body),rule,"isjo") then
						    is_type =is_type_return(rule_name,rule,"static")
							error_rule = rule .. ' >> ' .. k .. '=' .. body.. ' >> ' .. body
							ngx.shared.btwaf_data:incr(ip,100)
							fraction=fraction+100
							count=count+1
						end
					elseif type(body) == "string" and type(rule) == "table" then
					    if ngx_match(ngx.unescape_uri(body),rule[1],"isjo") then
						    is_type =is_type_return(rule_name,rule[2],"ip")
							error_rule = rule[1] .. ' >> ' .. k .. '=' .. body.. ' >> ' .. body
							ngx.shared.btwaf_data:incr(ip,rule[3])
							count=count+1
							fraction=fraction+rule[3]
						end
					end
				end
			end
		end
    end
    if count >=2 then return true end
    if fraction >=100 then return true end
	return false
end

local function args_urlencoded(request_args)
    if is_ngx_match2(args_rules,request_args,'args') then 
        write_log('args','ip攻击次数多被拦截2222')
		return_html(config['get']['status'],get_html)
    end 
    if ngx.shared.btwaf_data:get(ip) >1000 then 
		return lan_ip('post','ip攻击次数多被拦截3333')
    end 
	if libinjection_args(request_args) then
		ngx.shared.btwaf_data:set(ip..'args','1',360)
		write_log('args','GET参数拦截2')
		return_html(config['get']['status'],get_html)
	end
end


local function args()
	if not config['get']['open'] or not is_site_config('get') then return false end	
	if count_sieze(uri_request_args)==0 then return false end 
	local list_data = nil
	rd_data={}
	if type(uri_request_args)=='table' then
		for k,v in pairs(uri_request_args)
		do
			if type(v)=='table' then
				table.insert(rd_data,de_dict2(k,v))
			end
		end
	end
	if rd_data then
		if arrlen(rd_data)>=1 then 
			for i,v in ipairs(rd_data) do 
				args_urlencoded(v)
				request_args=_process_json_args(v,uri_request_args)
			end
		else
			request_args=_process_json_args(rd_data,uri_request_args)
		end 
	else
		request_args =_process_json_args(uri_request_args)
	end
	if count_sieze(request_args)>=1000 then 
	    is_type="GET参数"
		error_rule = '参数太多GET传递的参数数量超过800,拒绝访问,如有误报请点击误报'
		write_log('args','参数太多GET传递的参数数量超过800,拒绝访问,如有误报请点击误报')
	    return_html_data('网站防火墙','您的请求带有不合法参数，已被网站管理员设置拦截','GET传递的参数数量超过800,拒绝访问','点击误报')
	end
	args_urlencoded(request_args)
end

local function url()
	if not config['get']['open'] or not is_site_config('get') then return false end
	if count_sieze(url_rules)==0 then return false end 
	if is_ngx_match(url_rules,uri,'url') then
		write_log('url','URL拦截')
		return_html(config['get']['status'],get_html)
		return true
	end
	args_urlencoded({uri})
	end

local function url_path()
	if site_config[server_name] == nil then return false end
	for _,rule in ipairs(site_config[server_name]['disable_path'])
	do
		if ngx_match(uri,rule,"isjo") then
			is_type='站点URL黑名单'
			write_log('path','站点URL黑名单')
			return_html(config['other']['status'],other_html)
			return true
		end
	end
	return false
end

local function url_ext()
	if site_config[server_name] == nil then return false end
	for _,rule in ipairs(site_config[server_name]['disable_ext'])
	do
		if ngx_match(uri,"\\."..rule.."$","isjo") then
			write_log('url_ext','URL拦截2')
			return_html(config['other']['status'],other_html)
			return true
		end
	end
	return false
end

local function url_rule_ex()
	if site_config[server_name] == nil then return false end
	if method == "POST" and not request_args then
		content_length=tonumber(request_header['content-length'])
		max_len = 640 * 102400000
		request_args = nil
		if content_length < max_len then
			ngx.req.read_body()
			request_args = ngx.req.get_post_args()
		end
	end
	for _,rule in ipairs(site_config[server_name]['url_rule'])
	do
		if ngx_match(uri,rule[1],"isjo") then
			if is_ngx_match(rule[2],uri_request_args,false) then
				write_log('url_rule','URL_路由拦截')
				return_html(config['other']['status'],other_html)
				return true
			end
			
			if method == "POST" and request_args ~= nil then 
				if is_ngx_match(rule[2],request_args,'post') then
					write_log('post','URL_路由拦截')
					return_html(config['other']['status'],other_html)
					return true
				end
			end
		end
	end
	return false
end

local function url_tell()
	if site_config[server_name] == nil then return false end
	for _,rule in ipairs(site_config[server_name]['url_tell'])
	do
		if ngx_match(uri,rule[1],"isjo") then
			if uri_request_args[rule[2]] ~= rule[3] then
				is_type="受保护的URL"
				write_log('url_tell','受保护的URL')
				return_html(config['other']['status'],other_html)
				return true
			end
		end
	end
	return false
end



local function get_btwaf_drop_ip()
	local data =  ngx.shared.drop_ip:get_keys(0)
	return data
end

local function remove_btwaf_drop_ip()
	if not uri_request_args['ip'] or not is_ipaddr(uri_request_args['ip']) then return get_return_state(true,'格式错误') end
	if ngx.shared.btwaf:get(cpath2 .. 'stop_ip') then
		ret=ngx.shared.btwaf:get(cpath2 .. 'stop_ip')
		ip_data=json.decode(ret)
        result=is_chekc_table(ip_data,uri_request_args['ip'])
        os.execute("sleep " .. 0.6)
        ret2=ngx.shared.btwaf:get(cpath2 .. 'stop_ip')
        ip_data2=json.decode(ret2)
        if result == 3 then
	    	for k,v in pairs(ip_data2)
		    do
		        if uri_request_args['ip'] == v['ip'] then 
		            v['time']=0
		        end
		    end
		end
	  	save_ip_on(ip_data2)
	end
	local token2 = ngx.md5(uri_request_args['ip'] .. '_' ..'return_cc_url')
    ngx.shared.btwaf:delete(token2)
	ngx.shared.drop_ip:delete(uri_request_args['ip'])
	ngx.shared.btwaf:delete(ngx.md5(uri_request_args['ip']))
	ngx.shared.btwaf_data:delete(uri_request_args['ip'])
	ngx.shared.btwaf_data:delete(uri_request_args['ip']..'_san')

	return get_return_state(true,uri_request_args['ip'] .. '已解封')
end

local function clean_btwaf_drop_ip()
	if ngx.shared.btwaf:get(cpath2 .. 'stop_ip') then
        ret2=ngx.shared.btwaf:get(cpath2 .. 'stop_ip')
        ip_data2=json.decode(ret2)
    	for k,v in pairs(ip_data2)
	    do
	            v['time']=0
	    end
	  	save_ip_on(ip_data2)
	  	os.execute("sleep " .. 2)
	end
	local data = get_btwaf_drop_ip()
	for _,value in ipairs(data)
	do
	    ngx.shared.btwaf_data:delete(value)
	    ngx.shared.btwaf:delete(ngx.md5(value))
		ngx.shared.drop_ip:delete(value)
		local token2 = ngx.md5(value .. '_' ..'return_cc_url')
		ngx.shared.btwaf:delete(token2)
		ngx.shared.btwaf_data:delete(value..'_san')
	end
	return get_return_state(true,'已解封所有IP')
end

local function get_btwaf_captcha_base64()
	local token = ngx.md5(ip..'base64')
	local count,_ = ngx.shared.btwaf:get(token)
	if count then
		if count > config['retry'] then
			local safe_count,_ = ngx.shared.drop_sum:get(ip)
			if not safe_count then
				ngx.shared.drop_sum:set(ip,1,86400)
				safe_count = 1
			else
				ngx.shared.drop_sum:incr(ip,1)
			end
			local lock_time = (config['retry_time'] * safe_count)
			if lock_time > 86400 then lock_time = 86400 end
			ngx.shared.drop_ip:set(ip,retry+1,lock_time)
			is_type='cc'
			lan_ip('cc','防火墙获取验证码接口遭到该IP攻击:  '..cycle..'秒内累计超过'..config['retry']..'次请求,封锁' .. lock_time .. '秒')
		else
			ngx.shared.btwaf:incr(token,1)
		end
	else
		ngx.shared.btwaf:set(token,1,config['retry_cycle'])
	end
	math.randomseed(tostring(os.time()):reverse():sub(1, 6))
	local n1 = math.random(1,200)
	ngx.shared.btwaf:set(ip..'__captcha',captcha_num2[tostring(n1)],180)
	file_name='/www/server/btwaf/captcha/'..n1..'_'..captcha_num2[tostring(n1)]..'.png'
	data=re_png(file_name)
	return get_return_state(true,ngx.encode_base64(data))
end


function min_route()
    if request_uri==nil then return false end 
	uri_check=split(request_uri,'?')
	if not uri_check[1] then return false end 
	if uri_check[1] == '/get_btwaf_captcha_base64' then 
		return_message(200,get_btwaf_captcha_base64())
	end
	if uri_check[1] == '/Verification_auth_btwaf' then 
		return_message(200,Verification_auth_btwaf())
	end
	if uri_check[1] == '/a20be899_96a6_40b2_88ba_32f1f75f1552_yanzheng_ip.php' then
	    return_message(200,yanzhengip("renji"))
	end
	if uri_check[1] == '/a20be899_96a6_40b2_88ba_32f1f75f1552_yanzheng_huadong.php' then
	    return_message(200,yanzhengip("huadong"))
	end
	if uri_check[1] == '/renji_296d626f_'..ngx.md5(ip)..'.js' then
	    return_message(200,yanzhengjs("renji"))
	end
	if uri_check[1] == '/huadong_296d626f_'..ngx.md5(ip)..'.js' then
	    return_message(200,yanzhengjs("huadong"))
	end
	if ngx.var.remote_addr ~= '127.0.0.1' then return false end
	if uri == '/get_btwaf_drop_ip' then
		return_message(200,get_btwaf_drop_ip())
	elseif uri == '/remove_btwaf_drop_ip' then
		return_message(200,remove_btwaf_drop_ip())
	elseif uri == '/clean_btwaf_drop_ip' then
		return_message(200,clean_btwaf_drop_ip())
	end
end

local function toASCII(str,type)
    temp_1=''
    for i = 1, string.len(str) do
        temp_2=string.byte(string.sub(str,i,i))
        if temp_1=='' then 
            if type==1 then temp_1=temp_2+1 else temp_1=temp_2 end 
        else
            if type==1 then temp_1=temp_1..temp_2+1 else temp_1=temp_1..temp_2 end
        end 
    end
    return temp_1
end 

function yanzhengip(type)
    if type=='renji' then 
        post_list_data=ngx.req.get_uri_args()
        if post_list_data['key'] ==nil or post_list_data['value']==nil or post_list_data['type']==nil then
            send_Verification_renji(type)
        end
        if post_list_data['key'] == ngx.md5(ip) and post_list_data['value']==ngx.md5(toASCII(ngx.md5(request_header['user-agent']),0)) and post_list_data['type']=='96c4e20a0e951f471d32dae103e83881' then 
            local token=''
            if request_header['user-agent']~=nil then 
            	token=ngx.md5(ip..request_header['user-agent']..server_name..type..today)
            else
            	token=ngx.md5(ip..server_name..type..today)
            end 
            jwt_value=ngx.md5(os.time()..ip)
            ngx.shared.btwaf:set(token,jwt_value,7200)
            ngx.header.Set_Cookie =token.."="..jwt_value..';'
            ngx.header.content_type = "application/json;"
            ngx.header.Cache_Control = "no-cache"
            ngx.status = 200
            ngx.say(token)
            ngx.exit(200)
        else 
            send_Verification_renji(type)
        end
    elseif type=='huadong' then 
        post_list_data=ngx.req.get_uri_args()
        if post_list_data['key'] ==nil or post_list_data['value']==nil or post_list_data['type']==nil then
            send_Verification_renji(type)
        end
        if post_list_data['key'] == ngx.md5(ip) and post_list_data['value']==ngx.md5(toASCII(ngx.md5(request_header['user-agent']),1)) and post_list_data['type']=='ad82060c2e67cc7e2cc47552a4fc1242' then 
            local token=''
            if request_header['user-agent']~=nil then 
            	token=ngx.md5(ip..request_header['user-agent']..server_name..type..today)
            else
            	token=ngx.md5(ip..server_name..type..today)
            end 
            jwt_value=ngx.md5(os.time()..ip)
            ngx.shared.btwaf:set(token,jwt_value,7200)
            ngx.header.Set_Cookie =token.."="..jwt_value..';'
            ngx.header.content_type = "application/json;"
            ngx.header.Cache_Control = "no-cache"
            ngx.status = 200
            ngx.say(token)
            ngx.exit(200)
        else 
            send_Verification_renji(type)
        end
    end
end

function yanzhengjs(type)
    if type=='renji' then 
    		jsbody22='var cx=cx||function(p,j){var h={},m=h.lib={},n=m.Base=function(){function a(){}return{extend:function(d){a.prototype=this;var c=new a;d&&c.mixIn(d);c.$super=this;return c},create:function(){var a=this.extend();a.init.apply(a,arguments);return a},init:function(){},mixIn:function(a){for(var c in a)a.hasOwnProperty(c)&&(this[c]=a[c]);a.hasOwnProperty("toString")&&(this.toString=a.toString)},clone:function(){return this.$super.extend(this)}}}(),b=m.WordArray=n.extend({init:function(a,d){a=this.words=a||[];this.sigBytes=d!=j?d:4*a.length},toString:function(a){return(a||q).stringify(this)},concat:function(a){var d=this.words,c=a.words,g=this.sigBytes,a=a.sigBytes;this.clamp();if(g%4)for(var f=0;f<a;f++)d[g+f>>>2]|=(c[f>>>2]>>>24-8*(f%4)&255)<<24-8*((g+f)%4);else if(65535<c.length)for(f=0;f<a;f+=4)d[g+f>>>2]=c[f>>>2];else d.push.apply(d,c);this.sigBytes+=a;return this},clamp:function(){var a=this.words,d=this.sigBytes;a[d>>>2]&=4294967295<<32-8*(d%4);a.length=p.ceil(d/4)},clone:function(){var a=n.clone.call(this);a.words=this.words.slice(0);return a},random:function(a){for(var d=[],c=0;c<a;c+=4)d.push(4294967296*p.random()|0);return b.create(d,a)}}),i=h.enc={},q=i.Hex={stringify:function(a){for(var d=a.words,a=a.sigBytes,c=[],g=0;g<a;g++){var f=d[g>>>2]>>>24-8*(g%4)&255;c.push((f>>>4).toString(16));c.push((f&15).toString(16))}return c.join("")},parse:function(a){for(var d=a.length,c=[],g=0;g<d;g+=2)c[g>>>3]|=parseInt(a.substr(g,2),16)<<24-4*(g%8);return b.create(c,d/2)}},k=i.Latin1={stringify:function(a){for(var d=a.words,a=a.sigBytes,c=[],g=0;g<a;g++)c.push(String.fromCharCode(d[g>>>2]>>>24-8*(g%4)&255));return c.join("")},parse:function(a){for(var d=a.length,c=[],g=0;g<d;g++)c[g>>>2]|=(a.charCodeAt(g)&255)<<24-8*(g%4);return b.create(c,d)}},l=i.Utf8={stringify:function(a){try{return decodeURIComponent(escape(k.stringify(a)))}catch(d){throw Error("Malformed UTF-8 data");}},parse:function(a){return k.parse(unescape(encodeURIComponent(a)))}},e=m.BufferedBlockAlgorithm=n.extend({reset:function(){this._data=b.create();this._nDataBytes=0},_append:function(a){"string"==typeof a&&(a=l.parse(a));this._data.concat(a);this._nDataBytes+=a.sigBytes},_process:function(a){var d=this._data,c=d.words,g=d.sigBytes,f=this.blockSize,o=g/(4*f),o=a?p.ceil(o):p.max((o|0)-this._minBufferSize,0),a=o*f,g=p.min(4*a,g);if(a){for(var e=0;e<a;e+=f)this._doProcessBlock(c,e);e=c.splice(0,a);d.sigBytes-=g}return b.create(e,g)},clone:function(){var a=n.clone.call(this);a._data=this._data.clone();return a},_minBufferSize:0});m.Hasher=e.extend({init:function(){this.reset()},reset:function(){e.reset.call(this);this._doReset()},update:function(a){this._append(a);this._process();return this},finalize:function(a){a&&this._append(a);this._doFinalize();return this._hash},clone:function(){var a=e.clone.call(this);a._hash=this._hash.clone();return a},blockSize:16,_createHelper:function(a){return function(d,c){return a.create(c).finalize(d)}},_createHmacHelper:function(a){return function(d,c){return r.HMAC.create(a,c).finalize(d)}}});var r=h.algo={};return h}(Math);(function(){var p=cx,j=p.lib.WordArray;p.enc.Base64={stringify:function(h){var m=h.words,j=h.sigBytes,b=this._map;h.clamp();for(var h=[],i=0;i<j;i+=3)for(var q=(m[i>>>2]>>>24-8*(i%4)&255)<<16|(m[i+1>>>2]>>>24-8*((i+1)%4)&255)<<8|m[i+2>>>2]>>>24-8*((i+2)%4)&255,k=0;4>k&&i+0.75*k<j;k++)h.push(b.charAt(q>>>6*(3-k)&63));if(m=b.charAt(64))for(;h.length%4;)h.push(m);return h.join("")},parse:function(h){var h=h.replace(/\\s/g,""),m=h.length,n=this._map,b=n.charAt(64);b&&(b=h.indexOf(b),-1!=b&&(m=b));for(var b=[],i=0,q=0;q<m;q++)if(q%4){var k=n.indexOf(h.charAt(q-1))<<2*(q%4),l=n.indexOf(h.charAt(q))>>>6-2*(q%4);b[i>>>2]|=(k|l)<<24-8*(i%4);i++}return j.create(b,i)},_map:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="}})();(function(p){function j(e,b,a,d,c,g,f){e=e+(b&a|~b&d)+c+f;return(e<<g|e>>>32-g)+b}function h(e,b,a,d,c,g,f){e=e+(b&d|a&~d)+c+f;return(e<<g|e>>>32-g)+b}function m(e,b,a,d,c,g,f){e=e+(b^a^d)+c+f;return(e<<g|e>>>32-g)+b}function n(e,b,a,d,c,g,f){e=e+(a^(b|~d))+c+f;return(e<<g|e>>>32-g)+b}var b=cx,i=b.lib,q=i.WordArray,i=i.Hasher,k=b.algo,l=[];(function(){for(var e=0;64>e;e++)l[e]=4294967296*p.abs(p.sin(e+1))|0})();k=k.MD5=i.extend({_doReset:function(){this._hash=q.create([1732584193,4023233417,2562383102,271733878])},_doProcessBlock:function(e,b){for(var a=0;16>a;a++){var d=b+a,c=e[d];e[d]=(c<<8|c>>>24)&16711935|(c<<24|c>>>8)&4278255360}for(var d=this._hash.words,c=d[0],g=d[1],f=d[2],o=d[3],a=0;64>a;a+=4)16>a?(c=j(c,g,f,o,e[b+a],7,l[a]),o=j(o,c,g,f,e[b+a+1],12,l[a+1]),f=j(f,o,c,g,e[b+a+2],17,l[a+2]),g=j(g,f,o,c,e[b+a+3],22,l[a+3])):32>a?(c=h(c,g,f,o,e[b+(a+1)%16],5,l[a]),o=h(o,c,g,f,e[b+(a+6)%16],9,l[a+1]),f=h(f,o,c,g,e[b+(a+11)%16],14,l[a+2]),g=h(g,f,o,c,e[b+a%16],20,l[a+3])):48>a?(c=m(c,g,f,o,e[b+(3*a+5)%16],4,l[a]),o=m(o,c,g,f,e[b+(3*a+8)%16],11,l[a+1]),f=m(f,o,c,g,e[b+(3*a+11)%16],16,l[a+2]),g=m(g,f,o,c,e[b+(3*a+14)%16],23,l[a+3])):(c=n(c,g,f,o,e[b+3*a%16],6,l[a]),o=n(o,c,g,f,e[b+(3*a+7)%16],10,l[a+1]),f=n(f,o,c,g,e[b+(3*a+14)%16],15,l[a+2]),g=n(g,f,o,c,e[b+(3*a+5)%16],21,l[a+3]));d[0]=d[0]+c|0;d[1]=d[1]+g|0;d[2]=d[2]+f|0;d[3]=d[3]+o|0},_doFinalize:function(){var b=this._data,i=b.words,a=8*this._nDataBytes,d=8*b.sigBytes;i[d>>>5]|=128<<24-d%32;i[(d+64>>>9<<4)+14]=(a<<8|a>>>24)&16711935|(a<<24|a>>>8)&4278255360;b.sigBytes=4*(i.length+1);this._process();b=this._hash.words;for(i=0;4>i;i++)a=b[i],b[i]=(a<<8|a>>>24)&16711935|(a<<24|a>>>8)&4278255360}});b.MD5=i._createHelper(k);b.HmacMD5=i._createHmacHelper(k)})(Math);(function(){var p=cx,j=p.lib,h=j.Base,m=j.WordArray,j=p.algo,n=j.EvpKDF=h.extend({cfg:h.extend({keySize:4,hasher:j.MD5,iterations:1}),init:function(b){this.cfg=this.cfg.extend(b)},compute:function(b,i){for(var h=this.cfg,k=h.hasher.create(),l=m.create(),e=l.words,j=h.keySize,h=h.iterations;e.length<j;){a&&k.update(a);var a=k.update(b).finalize(i);k.reset();for(var d=1;d<h;d++)a=k.finalize(a),k.reset();l.concat(a)}l.sigBytes=4*j;return l}});p.EvpKDF=function(b,i,h){return n.create(h).compute(b,i)}})();cx.lib.Cipher||function(p){var j=cx,h=j.lib,m=h.Base,n=h.WordArray,b=h.BufferedBlockAlgorithm,i=j.enc.Base64,q=j.algo.EvpKDF,k=h.Cipher=b.extend({cfg:m.extend(),createEncryptor:function(g,a){return this.create(this._ENC_XFORM_MODE,g,a)},createDecryptor:function(g,a){return this.create(this._DEC_XFORM_MODE,g,a)},init:function(a,f,b){this.cfg=this.cfg.extend(b);this._xformMode=a;this._key=f;this.reset()},reset:function(){b.reset.call(this);this._doReset()},process:function(a){this._append(a);return this._process()},finalize:function(a){a&&this._append(a);return this._doFinalize()},keySize:4,ivSize:4,_ENC_XFORM_MODE:1,_DEC_XFORM_MODE:2,_createHelper:function(){return function(a){return{encrypt:function(f,b,e){return("string"==typeof b?c:d).encrypt(a,f,b,e)},decrypt:function(f,b,e){return("string"==typeof b?c:d).decrypt(a,f,b,e)}}}}()});h.StreamCipher=k.extend({_doFinalize:function(){return this._process(!0)},blockSize:1});var l=j.mode={},e=h.BlockCipherMode=m.extend({createEncryptor:function(a,f){return this.Encryptor.create(a,f)},createDecryptor:function(a,f){return this.Decryptor.create(a,f)},init:function(a,f){this._cipher=a;this._iv=f}}),l=l.CBC=function(){function a(g,f,b){var d=this._iv;d?this._iv=p:d=this._prevBlock;for(var c=0;c<b;c++)g[f+c]^=d[c]}var f=e.extend();f.Encryptor=f.extend({processBlock:function(f,b){var d=this._cipher,c=d.blockSize;a.call(this,f,b,c);d.encryptBlock(f,b);this._prevBlock=f.slice(b,b+c)}});f.Decryptor=f.extend({processBlock:function(f,b){var d=this._cipher,c=d.blockSize,e=f.slice(b,b+c);d.decryptBlock(f,b);a.call(this,f,b,c);this._prevBlock=e}});return f}(),r=(j.pad={}).Pkcs7={pad:function(a,f){for(var b=4*f,b=b-a.sigBytes%b,d=b<<24|b<<16|b<<8|b,c=[],e=0;e<b;e+=4)c.push(d);b=n.create(c,b);a.concat(b)},unpad:function(a){a.sigBytes-=a.words[a.sigBytes-1>>>2]&255}};h.BlockCipher=k.extend({cfg:k.cfg.extend({mode:l,padding:r}),reset:function(){k.reset.call(this);var a=this.cfg,b=a.iv,a=a.mode;if(this._xformMode==this._ENC_XFORM_MODE)var d=a.createEncryptor;else d=a.createDecryptor,this._minBufferSize=1;this._mode=d.call(a,this,b&&b.words)},_doProcessBlock:function(a,b){this._mode.processBlock(a,b)},_doFinalize:function(){var a=this.cfg.padding;if(this._xformMode==this._ENC_XFORM_MODE){a.pad(this._data,this.blockSize);var b=this._process(!0)}else b=this._process(!0),a.unpad(b);return b},blockSize:4});var a=h.CipherParams=m.extend({init:function(a){this.mixIn(a)},toString:function(a){return(a||this.formatter).stringify(this)}}),l=(j.format={}).OpenSSL={stringify:function(a){var b=a.ciphertext,a=a.salt,b=(a?n.create([1398893684,1701076831]).concat(a).concat(b):b).toString(i);return b=b.replace(/(.{64})/g,"$1\\n")},parse:function(b){var b=i.parse(b),f=b.words;if(1398893684==f[0]&&1701076831==f[1]){var d=n.create(f.slice(2,4));f.splice(0,4);b.sigBytes-=16}return a.create({ciphertext:b,salt:d})}},d=h.SerializableCipher=m.extend({cfg:m.extend({format:l}),encrypt:function(b,f,d,c){var c=this.cfg.extend(c),e=b.createEncryptor(d,c),f=e.finalize(f),e=e.cfg;return a.create({ciphertext:f,key:d,iv:e.iv,algorithm:b,mode:e.mode,padding:e.padding,blockSize:b.blockSize,formatter:c.format})},decrypt:function(a,b,d,c){c=this.cfg.extend(c);b=this._parse(b,c.format);return a.createDecryptor(d,c).finalize(b.ciphertext)},_parse:function(a,b){return"string"==typeof a?b.parse(a):a}}),j=(j.kdf={}).OpenSSL={compute:function(b,d,c,e){e||(e=n.random(8));b=q.create({keySize:d+c}).compute(b,e);c=n.create(b.words.slice(d),4*c);b.sigBytes=4*d;return a.create({key:b,iv:c,salt:e})}},c=h.PasswordBasedCipher=d.extend({cfg:d.cfg.extend({kdf:j}),encrypt:function(a,b,c,e){e=this.cfg.extend(e);c=e.kdf.compute(c,a.keySize,a.ivSize);e.iv=c.iv;a=d.encrypt.call(this,a,b,c.key,e);a.mixIn(c);return a},decrypt:function(a,b,c,e){e=this.cfg.extend(e);b=this._parse(b,e.format);c=e.kdf.compute(c,a.keySize,a.ivSize,b.salt);e.iv=c.iv;return d.decrypt.call(this,a,b,c.key,e)}})}();(function(){function p(){for(var b=this._S,i=this._i,h=this._j,k=0,l=0;4>l;l++){var i=(i+1)%256,h=(h+b[i])%256,e=b[i];b[i]=b[h];b[h]=e;k|=b[(b[i]+b[h])%256]<<24-8*l}this._i=i;this._j=h;return k}var j=cx,h=j.lib.StreamCipher,m=j.algo,n=m.RC4=h.extend({_doReset:function(){for(var b=this._key,h=b.words,b=b.sigBytes,j=this._S=[],k=0;256>k;k++)j[k]=k;for(var l=k=0;256>k;k++){var e=k%b,l=(l+j[k]+(h[e>>>2]>>>24-8*(e%4)&255))%256,e=j[k];j[k]=j[l];j[l]=e}this._i=this._j=0},_doProcessBlock:function(b,h){b[h]^=p.call(this)},keySize:8,ivSize:0});j.RC4=h._createHelper(n);m=m.RC4Drop=n.extend({cfg:n.cfg.extend({drop:192}),_doReset:function(){n._doReset.call(this);for(var b=this.cfg.drop;0<b;b--)p.call(this)}});j.RC4Drop=h._createHelper(m)})();(function(){window.addEventListener("load",(function(){var wait=3;setTimeout(function(){var _id=document.getElementById("bt-info");time(_id);function time(o){if(wait=="0"){var key="'..ngx.md5(ip)..'",value="'..ngx.md5(request_header['user-agent'])..'";function stringtoHex(acSTR){var val="";for(var i=0;i<=acSTR.length-1;i++){var str=acSTR.charAt(i);var code=str.charCodeAt();val+=code};return val};function md5encode(word){return cx.MD5(word).toString()};c.get("/a20be899_96a6_40b2_88ba_32f1f75f1552_yanzheng_ip.php?type=96c4e20a0e951f471d32dae103e83881&key="+key+"&value="+md5encode(stringtoHex(value))+"",(function(t){location.reload();location.reload()}))}else{o.innerHTML=("正在进行人机识别，请稍等 "+wait+"秒");wait--;setTimeout(function(){time(o)},1000)}}},1000)}));var c={get:function(t,n){var e=new XMLHttpRequest;e.open("GET",t,!0),e.onreadystatechange=function(){(4==e.readyState&&200==e.status||304==e.status)&&n.call(this,e.responseText)},e.send()},post:function(t,n,e){var r=new XMLHttpRequest;r.open("POST",t,!0),r.setRequestHeader("Content-Type","application/x-www-form-urlencoded"),r.onreadystatechange=function(){4!=r.readyState||200!=r.status&&304!=r.status||e.call(this,r.responseText)},r.send(n)}}})();'
    		ngx.header.content_type = "text/html;charset=utf8"
    		ngx.header.Cache_Control = "no-cache"
    		ngx.say(jsbody22)
    		ngx.exit(200)
    elseif type=='huadong' then 
            jsbody22='var cx=cx||function(p,j){var h={},m=h.lib={},n=m.Base=function(){function a(){}return{extend:function(d){a.prototype=this;var c=new a;d&&c.mixIn(d);c.$super=this;return c},create:function(){var a=this.extend();a.init.apply(a,arguments);return a},init:function(){},mixIn:function(a){for(var c in a)a.hasOwnProperty(c)&&(this[c]=a[c]);a.hasOwnProperty("toString")&&(this.toString=a.toString)},clone:function(){return this.$super.extend(this)}}}(),b=m.WordArray=n.extend({init:function(a,d){a=this.words=a||[];this.sigBytes=d!=j?d:4*a.length},toString:function(a){return(a||q).stringify(this)},concat:function(a){var d=this.words,c=a.words,g=this.sigBytes,a=a.sigBytes;this.clamp();if(g%4)for(var f=0;f<a;f++)d[g+f>>>2]|=(c[f>>>2]>>>24-8*(f%4)&255)<<24-8*((g+f)%4);else if(65535<c.length)for(f=0;f<a;f+=4)d[g+f>>>2]=c[f>>>2];else d.push.apply(d,c);this.sigBytes+=a;return this},clamp:function(){var a=this.words,d=this.sigBytes;a[d>>>2]&=4294967295<<32-8*(d%4);a.length=p.ceil(d/4)},clone:function(){var a=n.clone.call(this);a.words=this.words.slice(0);return a},random:function(a){for(var d=[],c=0;c<a;c+=4)d.push(4294967296*p.random()|0);return b.create(d,a)}}),i=h.enc={},q=i.Hex={stringify:function(a){for(var d=a.words,a=a.sigBytes,c=[],g=0;g<a;g++){var f=d[g>>>2]>>>24-8*(g%4)&255;c.push((f>>>4).toString(16));c.push((f&15).toString(16))}return c.join("")},parse:function(a){for(var d=a.length,c=[],g=0;g<d;g+=2)c[g>>>3]|=parseInt(a.substr(g,2),16)<<24-4*(g%8);return b.create(c,d/2)}},k=i.Latin1={stringify:function(a){for(var d=a.words,a=a.sigBytes,c=[],g=0;g<a;g++)c.push(String.fromCharCode(d[g>>>2]>>>24-8*(g%4)&255));return c.join("")},parse:function(a){for(var d=a.length,c=[],g=0;g<d;g++)c[g>>>2]|=(a.charCodeAt(g)&255)<<24-8*(g%4);return b.create(c,d)}},l=i.Utf8={stringify:function(a){try{return decodeURIComponent(escape(k.stringify(a)))}catch(d){throw Error("Malformed UTF-8 data");}},parse:function(a){return k.parse(unescape(encodeURIComponent(a)))}},e=m.BufferedBlockAlgorithm=n.extend({reset:function(){this._data=b.create();this._nDataBytes=0},_append:function(a){"string"==typeof a&&(a=l.parse(a));this._data.concat(a);this._nDataBytes+=a.sigBytes},_process:function(a){var d=this._data,c=d.words,g=d.sigBytes,f=this.blockSize,o=g/(4*f),o=a?p.ceil(o):p.max((o|0)-this._minBufferSize,0),a=o*f,g=p.min(4*a,g);if(a){for(var e=0;e<a;e+=f)this._doProcessBlock(c,e);e=c.splice(0,a);d.sigBytes-=g}return b.create(e,g)},clone:function(){var a=n.clone.call(this);a._data=this._data.clone();return a},_minBufferSize:0});m.Hasher=e.extend({init:function(){this.reset()},reset:function(){e.reset.call(this);this._doReset()},update:function(a){this._append(a);this._process();return this},finalize:function(a){a&&this._append(a);this._doFinalize();return this._hash},clone:function(){var a=e.clone.call(this);a._hash=this._hash.clone();return a},blockSize:16,_createHelper:function(a){return function(d,c){return a.create(c).finalize(d)}},_createHmacHelper:function(a){return function(d,c){return r.HMAC.create(a,c).finalize(d)}}});var r=h.algo={};return h}(Math);(function(){var p=cx,j=p.lib.WordArray;p.enc.Base64={stringify:function(h){var m=h.words,j=h.sigBytes,b=this._map;h.clamp();for(var h=[],i=0;i<j;i+=3)for(var q=(m[i>>>2]>>>24-8*(i%4)&255)<<16|(m[i+1>>>2]>>>24-8*((i+1)%4)&255)<<8|m[i+2>>>2]>>>24-8*((i+2)%4)&255,k=0;4>k&&i+0.75*k<j;k++)h.push(b.charAt(q>>>6*(3-k)&63));if(m=b.charAt(64))for(;h.length%4;)h.push(m);return h.join("")},parse:function(h){var h=h.replace(/\\s/g,""),m=h.length,n=this._map,b=n.charAt(64);b&&(b=h.indexOf(b),-1!=b&&(m=b));for(var b=[],i=0,q=0;q<m;q++)if(q%4){var k=n.indexOf(h.charAt(q-1))<<2*(q%4),l=n.indexOf(h.charAt(q))>>>6-2*(q%4);b[i>>>2]|=(k|l)<<24-8*(i%4);i++}return j.create(b,i)},_map:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="}})();(function(p){function j(e,b,a,d,c,g,f){e=e+(b&a|~b&d)+c+f;return(e<<g|e>>>32-g)+b}function h(e,b,a,d,c,g,f){e=e+(b&d|a&~d)+c+f;return(e<<g|e>>>32-g)+b}function m(e,b,a,d,c,g,f){e=e+(b^a^d)+c+f;return(e<<g|e>>>32-g)+b}function n(e,b,a,d,c,g,f){e=e+(a^(b|~d))+c+f;return(e<<g|e>>>32-g)+b}var b=cx,i=b.lib,q=i.WordArray,i=i.Hasher,k=b.algo,l=[];(function(){for(var e=0;64>e;e++)l[e]=4294967296*p.abs(p.sin(e+1))|0})();k=k.MD5=i.extend({_doReset:function(){this._hash=q.create([1732584193,4023233417,2562383102,271733878])},_doProcessBlock:function(e,b){for(var a=0;16>a;a++){var d=b+a,c=e[d];e[d]=(c<<8|c>>>24)&16711935|(c<<24|c>>>8)&4278255360}for(var d=this._hash.words,c=d[0],g=d[1],f=d[2],o=d[3],a=0;64>a;a+=4)16>a?(c=j(c,g,f,o,e[b+a],7,l[a]),o=j(o,c,g,f,e[b+a+1],12,l[a+1]),f=j(f,o,c,g,e[b+a+2],17,l[a+2]),g=j(g,f,o,c,e[b+a+3],22,l[a+3])):32>a?(c=h(c,g,f,o,e[b+(a+1)%16],5,l[a]),o=h(o,c,g,f,e[b+(a+6)%16],9,l[a+1]),f=h(f,o,c,g,e[b+(a+11)%16],14,l[a+2]),g=h(g,f,o,c,e[b+a%16],20,l[a+3])):48>a?(c=m(c,g,f,o,e[b+(3*a+5)%16],4,l[a]),o=m(o,c,g,f,e[b+(3*a+8)%16],11,l[a+1]),f=m(f,o,c,g,e[b+(3*a+11)%16],16,l[a+2]),g=m(g,f,o,c,e[b+(3*a+14)%16],23,l[a+3])):(c=n(c,g,f,o,e[b+3*a%16],6,l[a]),o=n(o,c,g,f,e[b+(3*a+7)%16],10,l[a+1]),f=n(f,o,c,g,e[b+(3*a+14)%16],15,l[a+2]),g=n(g,f,o,c,e[b+(3*a+5)%16],21,l[a+3]));d[0]=d[0]+c|0;d[1]=d[1]+g|0;d[2]=d[2]+f|0;d[3]=d[3]+o|0},_doFinalize:function(){var b=this._data,i=b.words,a=8*this._nDataBytes,d=8*b.sigBytes;i[d>>>5]|=128<<24-d%32;i[(d+64>>>9<<4)+14]=(a<<8|a>>>24)&16711935|(a<<24|a>>>8)&4278255360;b.sigBytes=4*(i.length+1);this._process();b=this._hash.words;for(i=0;4>i;i++)a=b[i],b[i]=(a<<8|a>>>24)&16711935|(a<<24|a>>>8)&4278255360}});b.MD5=i._createHelper(k);b.HmacMD5=i._createHmacHelper(k)})(Math);(function(){var p=cx,j=p.lib,h=j.Base,m=j.WordArray,j=p.algo,n=j.EvpKDF=h.extend({cfg:h.extend({keySize:4,hasher:j.MD5,iterations:1}),init:function(b){this.cfg=this.cfg.extend(b)},compute:function(b,i){for(var h=this.cfg,k=h.hasher.create(),l=m.create(),e=l.words,j=h.keySize,h=h.iterations;e.length<j;){a&&k.update(a);var a=k.update(b).finalize(i);k.reset();for(var d=1;d<h;d++)a=k.finalize(a),k.reset();l.concat(a)}l.sigBytes=4*j;return l}});p.EvpKDF=function(b,i,h){return n.create(h).compute(b,i)}})();cx.lib.Cipher||function(p){var j=cx,h=j.lib,m=h.Base,n=h.WordArray,b=h.BufferedBlockAlgorithm,i=j.enc.Base64,q=j.algo.EvpKDF,k=h.Cipher=b.extend({cfg:m.extend(),createEncryptor:function(g,a){return this.create(this._ENC_XFORM_MODE,g,a)},createDecryptor:function(g,a){return this.create(this._DEC_XFORM_MODE,g,a)},init:function(a,f,b){this.cfg=this.cfg.extend(b);this._xformMode=a;this._key=f;this.reset()},reset:function(){b.reset.call(this);this._doReset()},process:function(a){this._append(a);return this._process()},finalize:function(a){a&&this._append(a);return this._doFinalize()},keySize:4,ivSize:4,_ENC_XFORM_MODE:1,_DEC_XFORM_MODE:2,_createHelper:function(){return function(a){return{encrypt:function(f,b,e){return("string"==typeof b?c:d).encrypt(a,f,b,e)},decrypt:function(f,b,e){return("string"==typeof b?c:d).decrypt(a,f,b,e)}}}}()});h.StreamCipher=k.extend({_doFinalize:function(){return this._process(!0)},blockSize:1});var l=j.mode={},e=h.BlockCipherMode=m.extend({createEncryptor:function(a,f){return this.Encryptor.create(a,f)},createDecryptor:function(a,f){return this.Decryptor.create(a,f)},init:function(a,f){this._cipher=a;this._iv=f}}),l=l.CBC=function(){function a(g,f,b){var d=this._iv;d?this._iv=p:d=this._prevBlock;for(var c=0;c<b;c++)g[f+c]^=d[c]}var f=e.extend();f.Encryptor=f.extend({processBlock:function(f,b){var d=this._cipher,c=d.blockSize;a.call(this,f,b,c);d.encryptBlock(f,b);this._prevBlock=f.slice(b,b+c)}});f.Decryptor=f.extend({processBlock:function(f,b){var d=this._cipher,c=d.blockSize,e=f.slice(b,b+c);d.decryptBlock(f,b);a.call(this,f,b,c);this._prevBlock=e}});return f}(),r=(j.pad={}).Pkcs7={pad:function(a,f){for(var b=4*f,b=b-a.sigBytes%b,d=b<<24|b<<16|b<<8|b,c=[],e=0;e<b;e+=4)c.push(d);b=n.create(c,b);a.concat(b)},unpad:function(a){a.sigBytes-=a.words[a.sigBytes-1>>>2]&255}};h.BlockCipher=k.extend({cfg:k.cfg.extend({mode:l,padding:r}),reset:function(){k.reset.call(this);var a=this.cfg,b=a.iv,a=a.mode;if(this._xformMode==this._ENC_XFORM_MODE)var d=a.createEncryptor;else d=a.createDecryptor,this._minBufferSize=1;this._mode=d.call(a,this,b&&b.words)},_doProcessBlock:function(a,b){this._mode.processBlock(a,b)},_doFinalize:function(){var a=this.cfg.padding;if(this._xformMode==this._ENC_XFORM_MODE){a.pad(this._data,this.blockSize);var b=this._process(!0)}else b=this._process(!0),a.unpad(b);return b},blockSize:4});var a=h.CipherParams=m.extend({init:function(a){this.mixIn(a)},toString:function(a){return(a||this.formatter).stringify(this)}}),l=(j.format={}).OpenSSL={stringify:function(a){var b=a.ciphertext,a=a.salt,b=(a?n.create([1398893684,1701076831]).concat(a).concat(b):b).toString(i);return b=b.replace(/(.{64})/g,"$1\\n")},parse:function(b){var b=i.parse(b),f=b.words;if(1398893684==f[0]&&1701076831==f[1]){var d=n.create(f.slice(2,4));f.splice(0,4);b.sigBytes-=16}return a.create({ciphertext:b,salt:d})}},d=h.SerializableCipher=m.extend({cfg:m.extend({format:l}),encrypt:function(b,f,d,c){var c=this.cfg.extend(c),e=b.createEncryptor(d,c),f=e.finalize(f),e=e.cfg;return a.create({ciphertext:f,key:d,iv:e.iv,algorithm:b,mode:e.mode,padding:e.padding,blockSize:b.blockSize,formatter:c.format})},decrypt:function(a,b,d,c){c=this.cfg.extend(c);b=this._parse(b,c.format);return a.createDecryptor(d,c).finalize(b.ciphertext)},_parse:function(a,b){return"string"==typeof a?b.parse(a):a}}),j=(j.kdf={}).OpenSSL={compute:function(b,d,c,e){e||(e=n.random(8));b=q.create({keySize:d+c}).compute(b,e);c=n.create(b.words.slice(d),4*c);b.sigBytes=4*d;return a.create({key:b,iv:c,salt:e})}},c=h.PasswordBasedCipher=d.extend({cfg:d.cfg.extend({kdf:j}),encrypt:function(a,b,c,e){e=this.cfg.extend(e);c=e.kdf.compute(c,a.keySize,a.ivSize);e.iv=c.iv;a=d.encrypt.call(this,a,b,c.key,e);a.mixIn(c);return a},decrypt:function(a,b,c,e){e=this.cfg.extend(e);b=this._parse(b,e.format);c=e.kdf.compute(c,a.keySize,a.ivSize,b.salt);e.iv=c.iv;return d.decrypt.call(this,a,b,c.key,e)}})}();(function(){function p(){for(var b=this._S,i=this._i,h=this._j,k=0,l=0;4>l;l++){var i=(i+1)%256,h=(h+b[i])%256,e=b[i];b[i]=b[h];b[h]=e;k|=b[(b[i]+b[h])%256]<<24-8*l}this._i=i;this._j=h;return k}var j=cx,h=j.lib.StreamCipher,m=j.algo,n=m.RC4=h.extend({_doReset:function(){for(var b=this._key,h=b.words,b=b.sigBytes,j=this._S=[],k=0;256>k;k++)j[k]=k;for(var l=k=0;256>k;k++){var e=k%b,l=(l+j[k]+(h[e>>>2]>>>24-8*(e%4)&255))%256,e=j[k];j[k]=j[l];j[l]=e}this._i=this._j=0},_doProcessBlock:function(b,h){b[h]^=p.call(this)},keySize:8,ivSize:0});j.RC4=h._createHelper(n);m=m.RC4Drop=n.extend({cfg:n.cfg.extend({drop:192}),_doReset:function(){n._doReset.call(this);for(var b=this.cfg.drop;0<b;b--)p.call(this)}});j.RC4Drop=h._createHelper(m)})();(function(){window.addEventListener("load",(function(){var theID=document.getElementById("bt-info"),key="'..ngx.md5(ip)..'",value="'..ngx.md5(request_header['user-agent'])..'";function stringtoHex(acSTR){var val="";for(var i=0;i<=acSTR.length-1;i++){var str=acSTR.charAt(i);var code=str.charCodeAt();val+=parseInt(code)+1};return val};function md5encode(word){return cx.MD5(word).toString()};if(theID){var wait=3;setTimeout(function(){var _id=document.getElementById("bt-info");time(_id);function time(o){if(wait=="0"){c.get("/huadong_296d626f_%s.js?id=%s&key="+key+"&value="+md5encode(stringtoHex(value))+"",(function(t){location.reload();location.reload()}))}else{o.innerHTML=("正在进行人机识别，请稍等 "+wait+"秒");wait--;setTimeout(function(){time(o)},1000)}}},1000)}else{var slider=new SliderTools({el:document.querySelector(".slider"),});slider.on("complete",function(){c.get("/a20be899_96a6_40b2_88ba_32f1f75f1552_yanzheng_huadong.php?type=ad82060c2e67cc7e2cc47552a4fc1242&key="+key+"&value="+md5encode(stringtoHex(value))+"",(function(t){location.reload();location.reload()}))})}}));var c={get:function(t,n){var e=new XMLHttpRequest;e.open("GET",t,!0),e.onreadystatechange=function(){(4==e.readyState&&200==e.status||304==e.status)&&n.call(this,e.responseText)},e.send()},post:function(t,n,e){var r=new XMLHttpRequest;r.open("POST",t,!0),r.setRequestHeader("Content-Type","application/x-www-form-urlencoded"),r.onreadystatechange=function(){4!=r.readyState||200!=r.status&&304!=r.status||e.call(this,r.responseText)},r.send(n)}}})();(function webpackUniversalModuleDefinition(root,factory){if(typeof exports==="object"&&typeof module==="object")module.exports=factory();else if(typeof define==="function"&&define.amd)define([],factory);else if(typeof exports==="object")exports["SliderTools"]=factory();else root["SliderTools"]=factory()})(self,function(){return(function(){"use strict";var __webpack_exports__={};function _typeof(obj){"@babel/helpers - typeof";if(typeof Symbol==="function"&&typeof Symbol.iterator==="symbol"){_typeof=function _typeof(obj){return typeof obj}}else{_typeof=function _typeof(obj){return obj&&typeof Symbol==="function"&&obj.constructor===Symbol&&obj!==Symbol.prototype?"symbol":typeof obj}}return _typeof(obj)}function EventEmitter(){this._events={}}EventEmitter.prototype.on=function(eventName,listener){if(!eventName||!listener)return;if(!util.isValidListener(listener)){throw new TypeError("listener must be a function");}var events=this._events;var listeners=events[eventName]=events[eventName]||[];var listenerIsWrapped=_typeof(listener)==="object";if(util.indexOf(listeners,listener)===-1){listeners.push(listenerIsWrapped?listener:{listener:listener,once:false})}return this};EventEmitter.prototype.once=function(eventName,listener){return this.on(eventName,{listener:listener,once:true})};EventEmitter.prototype.off=function(eventName,listener){var listeners=this._events[eventName];if(!listeners)return;var index;for(var i=0,len=listeners.length;i<len;i++){if(listeners[i]&&listeners[i].listener===listener){index=i;break}}if(typeof index!=="undefined"){listeners.splice(index,1,null)}return this};EventEmitter.prototype.emit=function(eventName,args){var listeners=this._events[eventName];if(!listeners)return;for(var i=0;i<listeners.length;i++){var listener=listeners[i];if(listener){listener.listener.apply(this,args||[]);if(listener.once){this.off(eventName,listener.listener)}}}return this};var util={extend:function extend(target){for(var i=1,len=arguments.length;i<len;i++){for(var prop in arguments[i]){if(arguments[i].hasOwnProperty(prop)){target[prop]=arguments[i][prop]}}}return target},setClassName:function setClassName(selector,className){selector.className=className},addClass:function addClass(selector,className){selector.classList.add(className)},setInlineStyle:function setInlineStyle(selector,attr,content){var length=selector.length;for(var i=0;i<length;i++){selector[i].style[attr]=content}},isValidListener:function isValidListener(listener){if(typeof listener==="function"){return true}else if(listener&&_typeof(listener)==="object"){return util.isValidListener(listener.listener)}else{return false}},addCSS:function addCSS(cssText){var style=document.createElement("style"),head=document.head||document.getElementsByTagName("head")[0];style.type="text/css";if(style.styleSheet){var func=function func(){try{style.styleSheet.cssText=cssText}catch(e){}};if(style.styleSheet.disabled){setTimeout(func,10)}else{func()}}else{var textNode=document.createTextNode(cssText);style.appendChild(textNode)}head.appendChild(style)},indexOf:function indexOf(array,item){if(array.indexOf){return array.indexOf(item)}else{var result=-1;for(var i=0,len=array.length;i<len;i++){if(array[i]===item){result=i;break}}return result}}};function SliderTools(options){this.options=util.extend({},this.constructor.defaultOptions,options);this.init();this.bindEvents();this.diffX=0;this.flag=false}SliderTools.defaultOptions={el:document.body};var proto=SliderTools.prototype=new EventEmitter();proto.constructor=SliderTools;proto.init=function(){this.createSlider();this.getElements()};proto.createSlider=function(){this.options.el.innerHTML=\'<div id="slider"><div class="drag_bg"></div><div class="drag_text" onselectstart="return false;" unselectable="on">拖动滑块验证</div><div class="handler handler_bg"></div></div>\';util.addCSS(\'ul, li {    list-style: none;    }    a {    text-decoration: none;    }    .wrap {    width: 300px;    height: 350px;    text-align: center;    margin: 150px auto;    }    .inner {    padding: 15px;    }    .clearfix {    overflow: hidden;    _zoom: 1;    }    .none {    display: none;    }    #slider {    position: relative;    background-color: #e8e8e8;    width: 300px;    height: 34px;    line-height: 34px;    text-align: center;    }    #slider .handler {    position: absolute;    top: 0px;    left: 0px;    width: 40px;    height: 32px;    border: 1px solid #ccc;    cursor: move; transition: all .2s ease}    .handler_bg {    background: #fff    url("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAA3hpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkIj8+IDx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IkFkb2JlIFhNUCBDb3JlIDUuNS1jMDIxIDc5LjE1NTc3MiwgMjAxNC8wMS8xMy0xOTo0NDowMCAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wTU09Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9tbS8iIHhtbG5zOnN0UmVmPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvc1R5cGUvUmVzb3VyY2VSZWYjIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtcE1NOk9yaWdpbmFsRG9jdW1lbnRJRD0ieG1wLmRpZDo0ZDhlNWY5My05NmI0LTRlNWQtOGFjYi03ZTY4OGYyMTU2ZTYiIHhtcE1NOkRvY3VtZW50SUQ9InhtcC5kaWQ6NTEyNTVEMURGMkVFMTFFNEI5NDBCMjQ2M0ExMDQ1OUYiIHhtcE1NOkluc3RhbmNlSUQ9InhtcC5paWQ6NTEyNTVEMUNGMkVFMTFFNEI5NDBCMjQ2M0ExMDQ1OUYiIHhtcDpDcmVhdG9yVG9vbD0iQWRvYmUgUGhvdG9zaG9wIENDIDIwMTQgKE1hY2ludG9zaCkiPiA8eG1wTU06RGVyaXZlZEZyb20gc3RSZWY6aW5zdGFuY2VJRD0ieG1wLmlpZDo2MTc5NzNmZS02OTQxLTQyOTYtYTIwNi02NDI2YTNkOWU5YmUiIHN0UmVmOmRvY3VtZW50SUQ9InhtcC5kaWQ6NGQ4ZTVmOTMtOTZiNC00ZTVkLThhY2ItN2U2ODhmMjE1NmU2Ii8+IDwvcmRmOkRlc2NyaXB0aW9uPiA8L3JkZjpSREY+IDwveDp4bXBtZXRhPiA8P3hwYWNrZXQgZW5kPSJyIj8+YiRG4AAAALFJREFUeNpi/P//PwMlgImBQkA9A+bOnfsIiBOxKcInh+yCaCDuByoswaIOpxwjciACFegBqZ1AvBSIS5OTk/8TkmNEjwWgQiUgtQuIjwAxUF3yX3xyGIEIFLwHpKyAWB+I1xGSwxULIGf9A7mQkBwTlhBXAFLHgPgqEAcTkmNCU6AL9d8WII4HOvk3ITkWJAXWUMlOoGQHmsE45ViQ2KuBuASoYC4Wf+OUYxz6mQkgwAAN9mIrUReCXgAAAABJRU5ErkJggg==")    no-repeat center;    }    .handler_ok_bg {    background: #fff    url("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAA3hpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkIj8+IDx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IkFkb2JlIFhNUCBDb3JlIDUuNS1jMDIxIDc5LjE1NTc3MiwgMjAxNC8wMS8xMy0xOTo0NDowMCAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wTU09Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9tbS8iIHhtbG5zOnN0UmVmPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvc1R5cGUvUmVzb3VyY2VSZWYjIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtcE1NOk9yaWdpbmFsRG9jdW1lbnRJRD0ieG1wLmRpZDo0ZDhlNWY5My05NmI0LTRlNWQtOGFjYi03ZTY4OGYyMTU2ZTYiIHhtcE1NOkRvY3VtZW50SUQ9InhtcC5kaWQ6NDlBRDI3NjVGMkQ2MTFFNEI5NDBCMjQ2M0ExMDQ1OUYiIHhtcE1NOkluc3RhbmNlSUQ9InhtcC5paWQ6NDlBRDI3NjRGMkQ2MTFFNEI5NDBCMjQ2M0ExMDQ1OUYiIHhtcDpDcmVhdG9yVG9vbD0iQWRvYmUgUGhvdG9zaG9wIENDIDIwMTQgKE1hY2ludG9zaCkiPiA8eG1wTU06RGVyaXZlZEZyb20gc3RSZWY6aW5zdGFuY2VJRD0ieG1wLmlpZDphNWEzMWNhMC1hYmViLTQxNWEtYTEwZS04Y2U5NzRlN2Q4YTEiIHN0UmVmOmRvY3VtZW50SUQ9InhtcC5kaWQ6NGQ4ZTVmOTMtOTZiNC00ZTVkLThhY2ItN2U2ODhmMjE1NmU2Ii8+IDwvcmRmOkRlc2NyaXB0aW9uPiA8L3JkZjpSREY+IDwveDp4bXBtZXRhPiA8P3hwYWNrZXQgZW5kPSJyIj8+k+sHwwAAASZJREFUeNpi/P//PwMyKD8uZw+kUoDYEYgloMIvgHg/EM/ptHx0EFk9I8wAoEZ+IDUPiIMY8IN1QJwENOgj3ACo5gNAbMBAHLgAxA4gQ5igAnNJ0MwAVTsX7IKyY7L2UNuJAf+AmAmJ78AEDTBiwGYg5gbifCSxFCZoaBMCy4A4GOjnH0D6DpK4IxNSVIHAfSDOAeLraJrjgJp/AwPbHMhejiQnwYRmUzNQ4VQgDQqXK0ia/0I17wJiPmQNTNBEAgMlQIWiQA2vgWw7QppBekGxsAjIiEUSBNnsBDWEAY9mEFgMMgBk00E0iZtA7AHEctDQ58MRuA6wlLgGFMoMpIG1QFeGwAIxGZo8GUhIysmwQGSAZgwHaEZhICIzOaBkJkqyM0CAAQDGx279Jf50AAAAAABJRU5ErkJggg==")    no-repeat center;    }    #slider .drag_bg {    background-color: #7ac23c;    height: 34px;    width: 0px;transition:all .2s ease       }    #slider .drag_text {    position: absolute;    top: 0px;    width: 300px;    -moz-user-select: none;    -webkit-user-select: none;    user-select: none;    -o-user-select: none;    -ms-user-select: none;    }    .unselect {    -moz-user-select: none;    -webkit-user-select: none;    -ms-user-select: none;    }    .slide_ok {    color: #fff;    }\')};proto.getElements=function(){this.slider=document.querySelector("#slider");this.drag_bg=document.querySelector(".drag_bg");this.handler=document.querySelector(".handler")};proto.bindEvents=function(){var self=this;self.handler.onmousedown=function(e){self.diffX=e.clientX-self.handler.offsetLeft;util.setClassName(self.slider,"unselect");util.setInlineStyle([self.handler,self.drag_bg],"transition","none");document.onmousemove=function(e){var deltaX=e.clientX-self.diffX;if(deltaX>=self.slider.offsetWidth-self.handler.offsetWidth){deltaX=self.slider.offsetWidth-self.handler.offsetWidth;self.flag=true}else if(deltaX<=0){deltaX=0;self.flag=false}else{self.flag=false}util.setInlineStyle([self.handler],"left",deltaX+"px");util.setInlineStyle([self.drag_bg],"width",deltaX+"px")};document.onmouseup=function(){util.setInlineStyle([self.handler,self.drag_bg],"transition","all .2s ease");util.setClassName(self.slider,"");if(self.flag){util.setClassName(self.slider,"slide_ok");util.addClass(self.handler,"handler_ok_bg");self.handler.onmousedown=null;self.emit("complete")}else{util.setInlineStyle([self.handler],"left",0+"px");util.setInlineStyle([self.drag_bg],"width",0+"px")}document.onmousemove=null;document.onmouseup=null}};self.handler.ontouchstart=function(e){self.diffX=e.touches[0].clientX-self.handler.offsetLeft;util.setClassName(self.slider,"unselect");util.setInlineStyle([self.handler,self.drag_bg],"transition","none");e.preventDefault();document.ontouchmove=function(e){var deltaX=e.touches[0].clientX-self.diffX;if(deltaX>=self.slider.offsetWidth-self.handler.offsetWidth){deltaX=self.slider.offsetWidth-self.handler.offsetWidth;self.flag=true}else if(deltaX<=0){deltaX=0;self.flag=false}else{self.flag=false}util.setInlineStyle([self.handler],"left",deltaX+"px");util.setInlineStyle([self.drag_bg],"width",deltaX+"px");e.preventDefault()};document.ontouchend=function(){util.setInlineStyle([self.handler,self.drag_bg],"transition","all .2s ease");util.setClassName(self.slider,"");if(self.flag){util.setClassName(self.slider,"slide_ok");util.addClass(self.handler,"handler_ok_bg");self.handler.onmousedown=null;self.emit("complete")}else{util.setInlineStyle([self.handler],"left",0+"px");util.setInlineStyle([self.drag_bg],"width",0+"px")}document.ontouchmove=null;document.ontouchend=null;e.preventDefault();}};};__webpack_exports__["default"]=(SliderTools);__webpack_exports__=__webpack_exports__.default;return __webpack_exports__})()});'
    		ngx.header.content_type = "text/html;charset=utf8"
    		ngx.header.Cache_Control = "no-cache"
    		ngx.say(jsbody22)
    		ngx.exit(200)
    end 
end 


function get_server_name_waf()
	local c_name = ngx.var.server_name
	local my_name = ngx.shared.btwaf:get(c_name)
	if my_name then return my_name end
	local tmp = read_file_body(cpath .. '/domains.json')
	if not tmp then return c_name end
	local domains = json.decode(tmp)
	for _,v in ipairs(domains)
	do
		for _,d_name in ipairs(v['domains'])
		do
			if c_name == d_name then
				ngx.shared.btwaf:set(c_name,v['name'],3600)
				return v['name']
			end
		end
	end
	if c_name =='_' then 
	    c_name="未绑定域名"
	   -- return ngx.exit(404)
	end 
	return c_name
end

local function return_zhi()
    return require "zhi"
end 

local function zhizu_ua_chkec(ua)
    ua_list2=return_zhi()
	if ua_list2 ~= nil then
		for _,k in ipairs(ua_list2['types'])
		do
				if k['ua_key'] ~= nil then
					local fa=string.find(string.lower(tostring(ua)),string.lower(tostring(k['ua_key'])))
					if fa ~= nil then
						return tonumber(k['id']),k['host_key']
					end
				end
		end
	end
end

local function get_zhizu_json(name)
    if ngx.shared.btwaf_data:get(cpath..name..'reptile') then return ngx.shared.btwaf_data:get(cpath..name..'reptile') end
	data = read_file_body(cpath .. tostring(name) ..'.json')
	if not data then 
		data={}
	end 
	ngx.shared.btwaf_data:set(cpath..name..'reptile',data,10000)
	return data
end

local function zhizu_chekc(name,ip)
	data=get_zhizu_json(name)
	local ok ,zhizhu_list_data = pcall(function()
		return json.decode(data)
	end)
	if not ok then
	    return false
	end
	if ngx.shared.spider:get(name) then 
	    if ngx.shared.spider:get(ip) then 
	        return true
	    end
	    return false
	end 
	ngx.shared.spider:set(name,'1',86400)
	for _,k in ipairs(zhizhu_list_data)
	do
	    ngx.shared.spider:set(k,'1',86400)
	end
    if ngx.shared.spider:get(ip) then 
        return true
    end
    return false
end

local function  host_pachong(ip,id,ua_key)
	if not ip then return 33 end
	if not id then return 33 end
	if not ua_key then return 33 end
	local key_id=ngx.shared.btwaf:get(ip..'baidu')
	if key_id == nil then 
		local r,err= resolver:new{
                nameservers = {"8.8.8.8", {"114.114.114.114", 53} },
                retrans = 5,  
                timeout = 2000}
        if not r then return 1888 end
		local data11111=r:reverse_query(tostring(ip))
		if not data11111 then 
			return 33
		end
		if type(data11111)~='table' then return 1888 end
		if data11111['errcode'] then return 1888 end 
		if not data11111[1] then return 1888 end 
		if not  data11111[1]['ptrdname'] then return 1888 end  
		local types=string.find(string.lower(tostring(data11111[1]['ptrdname'])),string.lower(tostring(ua_key)))
		if types~=nil then 
		    write_file2(cpath..'/zhizhu'..id..'.json',ip.."\n")
			ngx.shared.btwaf:set(ip..'baidu',1,86400)
			return 2
		else
			return 35
		end
	else
		return 2
	end	
end

local function reptile_entrance(ua,ip)
    if ngx.shared.spider:get(ip) then return 2 end 
    if ngx.shared.btwaf:get(ip..'baidu') then return 2 end 
    if ngx.re.match(ip,':','ijo') then return 1 end 
	if not ip then return 1 end
	if not ua then return 1 end
	if ngx.re.match(ua,'curl','ijo') or ngx.re.match(ua,'java','ijo') or ngx.re.match(ua,'python','ijo') then return 1.1 end
	local reptile_id,get_ua_key22=zhizu_ua_chkec(ua)
	if not reptile_id then return 1.2 end
	if not  get_ua_key22 then return 1.3 end 
	if site_config[server_name]['spider']~=nil and site_config[server_name]['spider_status']~=nil then 
	    if site_config[server_name]['spider_status']==false then 
	        ngx.exit(404)
	    end 
	    if site_config[server_name]['spider'][reptile_id]~=nil then
	        if type(site_config[server_name]['spider'][reptile_id])=='table' then 
    	        if site_config[server_name]['spider'][reptile_id]['status']~=nil then 
        	        if not site_config[server_name]['spider'][reptile_id]['status'] then 
        	            if site_config[server_name]['spider'][reptile_id]['return']==nil then 
        	                ngx.exit(404)
        	            else
        	                ngx.exit(tonumber(site_config[server_name]['spider'][reptile_id]['return']))
        	            end
        	        end
        	    end
    	    end
    	end
	end
	if tonumber(reptile_id) == 3  then 
		if zhizu_chekc(reptile_id,ip) then
			return 2 
		else
			return 34
		end
	end
	if zhizu_chekc(reptile_id,ip) then
		return 2
	else
	    baidu_error_count=ngx.shared.btwaf_data:get(ip..'baidu_error')  
	    if not baidu_error_count then 
		    local ret=host_pachong(ip,reptile_id,get_ua_key22)
		    if ret~=2 then 
		       baidu_error_count=ngx.shared.btwaf_data:set(ip..'baidu_error',1,86400) 
		       return ret
		    end
		    return ret
	    elseif baidu_error_count>=1 then 
	        return 188
	    else
	        local ret=host_pachong(ip,reptile_id,get_ua_key22)
	        if ret~=2 then 
	            ngx.shared.btwaf_data:incr(ip..'baidu_error',1)
	            return ret
	        end
	        return ret
		end
	end
	return 66
end

local function X_Forwarded()
	if not config['get']['open'] or not is_site_config('get') then return false end	
	if is_ngx_match(args_rules,request_header['X-forwarded-For'],'args') then
		write_log('args','xxf拦截')
		return_html(config['get']['status'],get_html)
		return true
	end
	return false
end

local function ReadFileHelper(str)
	 if type(str)~='string' then return str end
	 res = string.gsub(str, "\r", "")
	 res = string.gsub(res, "\n", "")
    return res
end

local function table_key(tbl, key)
    if tbl == nil then
        return false
    end
    for k, v in pairs(tbl) do
        if k == key then
            return true
        end
    end
    return false
end

local function chsize(char)
	if not char then
		print("not char")
		return 0
	elseif char > 240 then
		return 4
	elseif char > 225 then
		return 3
	elseif char > 192 then
		return 2
	else
		return 1
	end
end

local function utf8sub(str, startChar, numChars)
	local startIndex = 1
	while startChar > 1 do
		local char = string.byte(str, startIndex)
		startIndex = startIndex + chsize(char)
		startChar = startChar - 1
	end

	local currentIndex = startIndex

	while numChars > 0 and currentIndex <= #str do
		local char = string.byte(str, currentIndex)
		currentIndex = currentIndex + chsize(char)
		numChars = numChars -1
	end
	return str:sub(startIndex, currentIndex - 1)
end

local function is_substitution(data)
    data=ngx.re.sub(data,"\\+",'\\+')
    return data
end

local function  post_data_chekc()
	if not config['post']['open'] or not is_site_config('post') then return false end
	content_length=tonumber(request_header['content-length'])
	if not content_length then return false end
	if content_length >108246867 then return false end
	if method =="POST" then
		return_post_data=return_post_data2()
		if not return_post_data then return false end 
		if return_post_data==3 then return false end 
				ngx.req.read_body()
		request_args2=ngx.req.get_body_data()
		if not request_args2 then 
		    request_args2=ngx.req.get_body_file()
			if request_args2==nil then return false end 
		    request_args2=read_file_body(request_args2)
		end
		if not request_args2  then return false end
		if not request_header['content-type'] then return false end
		if type(request_header['content-type']) ~= "string" then 
			if type(request_header['content-type']) ~= "string" then 
				return_error(13)
			end
		end
        local p, err = multipart.new(request_args2, ngx.var.http_content_type)
        if not p then
           return false 
        end
        if not ngx.re.match(ReadFileHelper(p['body']),is_substitution(ReadFileHelper(p['boundary2']))..'--$','ijo') then
           	return return_message(200,"btwaf is from-data error")
        end
        site_count=0
        local array = {}
        while true do
            local part_body, name, mime, filename,is_filename,header_data = p:parse_part()
		    if header_data then 
               header_data_check=ngx.re.gmatch(header_data,[[Content-Disposition: form-data]],'ijo')
               ret={}
	            while true do
        		    local m, err = header_data_check()
        	      	if m then 
        	      		table.insert(ret,m)
        	      	else
        	      		break
        	      	end 
	            end
	            if arrlen(ret)>1 then 
	                return return_message(200,"btwaf is from-data error2")
	            end 
            end 
            if not is_filename then
              break
            end
            site_count=site_count+1
			if is_filename then 
                filename_data=ngx.re.match(is_filename,'filename.+','ijo')
                if filename_data then
					is_type='webshell防御'
                     if ngx.re.match(filename_data[0],'php','ijo') then return lan_ip('disable_upload_ext','上传非法PHP文件被系统拦截,并且被封锁IP13')  end 
        	        if ngx.re.match(filename_data[0],'jsp','ijo') then return lan_ip('disable_upload_ext','上传非法PHP文件被系统拦截,并且被封锁IP14')  end
					if  config['from_data'] then 
						if not ngx.re.match(is_filename,'^Content-Disposition: form-data; name=".+"; filename=".+"Content-Type:','ijo') and not ngx.re.match(is_filename,'^Content-Disposition: form-data; name=".+"; filename=""Content-Type:','ijo') then 
							  is_type='恶意上传'
							  	if not ngx.re.match(is_filename,'^Content-Disposition: form-data; name="filename"$',"ijo") and not ngx.re.match(is_filename,'^Content-Disposition: form-data; name=".+"$',"ijo") then 
							        return return_error(20)
							  end 
						end
					end
				end
				if(#is_filename)>1000 then 
                    lan_ip('disable_upload_ext','非法上传文件名长度超过1000被系统拦截,并封锁IP15') 
                end 

            end
            if filename ~=nil then 
				is_type='webshell防御'
        	    if ngx.re.match(filename,'php','ijo') then return lan_ip('disable_upload_ext','上传非法PHP文件被系统拦截,并且被封锁IP15')  end 
        	    if ngx.re.match(filename,'jsp','ijo') then return lan_ip('disable_upload_ext','上传非法PHP文件被系统拦截,并且被封锁IP16')  end
				if ngx.re.match(filename,'name=','ijo') then return return_error(15) end 
				if (#filename)>=1000 then
        	        lan_ip('disable_upload_ext','非法上传文件名长度超过1000被系统拦截,并封锁IP15') 
        	    end 
            end
            if name ==nil then 
              if part_body then
                    if #part_body>30 then 
                        array[utf8sub(part_body,1,30)]=part_body
                    else
                        array[part_body]=part_body
                    end 
              end
            else
               if #name >300 then 
                  return_error(16)
               end
               
               if filename ==nil then
                   if table_key(array,name) then
                        for i=1, 1000 do
                            if not table_key(array,name..'_'..i) then 
                                 if #name>30 then 
                                    array[utf8sub(name,1,30)..'_'..i]=part_body 
                                 else
                                     array[name..'_'..i]=part_body 
                                 end 
                                 
                                 break
                            end 
                        end 
                    else
                        if #name >30 then 
                            array[utf8sub(name,1,30)]=part_body
                        else 
                            array[name]=part_body
                        end 
                   end
	               if type(part_body)=='string' then
    					if (#part_body) >=400000 then
    						write_log('post',name..'     参数值长度超过40w已被系统拦截')
    						return_html(config['post']['status'],post_html)
    						return true
    					end
	    			end
                else
                    if type(part_body) =='string' and  part_body ~=nil then 
					    if ngx.re.find(part_body,[[phpinfo\(]],'ijo') or ngx.re.find(part_body,[[\$_SERVER]],'ijo') or ngx.re.find(part_body,[[<\?php]],'ijo') or ngx.re.find(part_body,[[fputs]],'ijo') or ngx.re.find(part_body,[[file_put_contents]],'ijo') or ngx.re.find(part_body,[[file_get_contents]],'ijo') or ngx.re.find(part_body,[[eval\(]],'ijo') or ngx.re.find(part_body,[[\$_POST]],'ijo')  or ngx.re.find(part_body,[[\$_GET]],'ijo') or ngx.re.find(part_body,[[base64_decode\(]],'ijo') or ngx.re.find(part_body,[[\$_REQUEST]],'ijo') or ngx.re.find(part_body,[[assert\(]],'ijo') or ngx.re.find(part_body,[[copy\(]],'ijo') or ngx.re.find(part_body,[[create_function\(]],'ijo') or ngx.re.find(part_body,[[preg_replace\(]],'ijo') or ngx.re.find(part_body,[[preg_filter\(]],'ijo') or ngx.re.find(part_body,[[system\(]],'ijo') or ngx.re.find(part_body,[[header_register_callback\(]],'ijo') or ngx.re.find(part_body,[[curl_init\(]],'ijo') or ngx.re.find(part_body,[[curl_error\(]],'ijo') or ngx.re.find(part_body,[[fopen\(]],'ijo')  or ngx.re.find(part_body,[[stream_context_create\(]],'ijo') or ngx.re.find(part_body,[[fsockopen\(]],'ijo')  then
					        is_type='webshell防御'
                            lan_ip('disable_upload_ext','webshell防御.拦截木马上传,并被封锁IP')
                        end 
                    end 
               end
            end
        end
        if site_count==0 then
        	if  config['from_data'] then 
        		return return_error2('','4') 
        	end
        end
        if count_sieze(array)>=3000 then
            is_type='POST参数'
			error_rule = '参数太多POST传递的参数数量超过800,拒绝访问,如有误报请点击误报'
		    write_log('post','参数太多POST传递的参数数量超过800,拒绝访问,如有误报请点击误报')
		    return_html_data('网站防火墙','您的请求带有不合法参数，已被网站管理员设置拦截','网站防火墙提醒您multipart/from-data传递的参数数量超过800,拒绝访问','点击误报')
		end
		if array['_method']  and array['method'] and array['server[REQUEST_METHOD]'] then
		    is_type='ThinkPHP攻击'
			lan_ip('post','拦截ThinkPHP 5.x RCE 攻击')
		end
		if array['_method']  and array['method'] and array['server[]'] and array['get[]'] then
		    is_type='ThinkPHP攻击'
			lan_ip('post','拦截ThinkPHP 5.x RCE 攻击,并且被封锁IP')
		end
		if array['_method'] and ngx.re.match(array['_method'],'construct','ijo') then
		    is_type='ThinkPHP攻击'
			lan_ip('post','拦截ThinkPHP 5.x RCE 攻击,并且被封锁IP')
		end
-- 		return return_message(200,post_rules)
      post_urlencoded(_process_json_args(array))
	   for i,v in pairs(array) do 
            if ngx.re.match(i,'\\\\$','ijo') then 
                is_type='恶意上传'
                return lan_ip('disable_upload_ext','非法上传请求已被系统拦截,并且被封锁IP11') 
            end 
        end 
	end
end

function cc_increase_static()
	local keys = {"css","js","png","gif","ico","jpg","jpeg","bmp","flush","swf","pdf","rar","zip","doc","docx","xlsx"}
	for _,k in ipairs(keys)
	do
		local aa="/?.*\\."..k.."$"
		if ngx_match(uri,aa,"isjo") then
		    
			return true
		end
	end
	return false
end

local function cc_uri_white()
    if count_sieze(cc_uri_white_rules)==0 then return false end 
	if cc_increase_static() then return true end
	if is_ngx_match(cc_uri_white_rules,uri,false) then
		return true
	end
	if site_config[server_name] ~= nil then
		if is_ngx_match(site_config[server_name]['cc_uri_white'],uri,false) then
			return true
		end
	end
	return false
end



local function set_inser_cc()
	if not site_config[server_name] then return false end 
	if not site_config[server_name]['cc'] then return false end
	cc_automatic=false
	cc_time=nil
	cc_retry_cycle=nil
	if site_config[server_name]['cc_automatic'] or config['cc_automatic'] then cc_automatic=true end
	if config['cc_retry_cycle'] then 
	    cc_retry_cycle=config['cc_retry_cycle']
	    cc_time=config['cc_time']*5
	end
	if site_config[server_name]['cc_retry_cycle'] then 
	    cc_retry_cycle=site_config[server_name]['cc_retry_cycle']
	    cc_time=site_config[server_name]['cc_time']*5
	end
	if cc_automatic then
		if cc_time == nil then return false end
		if cc_retry_cycle==nil then return false end
		if not ngx.shared.btwaf:get('cc_automatic'..server_name) then
			ngx.shared.btwaf:set('cc_automatic'..server_name,1,cc_time)
		else
			ret22222=ngx.shared.btwaf:get('cc_automatic'..server_name)
			if (tonumber(ret22222)/2)>tonumber(cc_retry_cycle) then
			    if site_config[server_name] then 
    				site_config[server_name]['cc']['increase']=true
    				site_config[server_name]['cc']['cc_increase_type']='js'
				    renji("btwaf")
			    else 
			        return false
			    end
			else
			    ngx.shared.btwaf:incr('cc_automatic'..server_name,1)
			end
			
		end
	end
end

local function get_body_character_string()
   local char_string=config['uri_find']
   if not char_string then return false end
   if arrlen(char_string) ==0 then return false end
   if arrlen(char_string) >=1 then return char_string end
end

local function url_find(uri)
	local get_body=get_body_character_string()
	if get_body then
		for __,v in pairs(get_body)
		do
			if string.find(ngx.unescape_uri(request_uri),v) then
				ngx.exit(444)
			end
		end
	end
end

local function get_config_ua_white()
   local char_string=config['ua_white']
   if not char_string then return false end
   if arrlen(char_string) ==0 then return false end
   if arrlen(char_string) >=1 then return char_string end
end

function get_config_ua_black()
   local char_string=config['ua_black']
   if not char_string then return false end
   if arrlen(char_string) ==0 then return false end
   if arrlen(char_string) >=1 then return char_string end
end

local function ua_white()
	local ua=ngx.req.get_headers(20000)['user-agent']
	if not ua then return false end
	if type(ua) ~='string' then ngx.exit(200) end 
	local get_ua_list=get_config_ua_white()
	if arrlen(get_ua_list)==0 then return false end
	if get_ua_list then
		for __,v in pairs(get_ua_list)
		do
			if ngx.re.match(ua,v,'ijo') then
				return true
			end
		end
	end
	return false
end

local function ua_black()
	local ua=ngx.req.get_headers(20000)['user-agent']
	if not ua then return false end
	if type(ua) ~='string' then ngx.exit(200) end 
	local get_ua_list=get_config_ua_black()
	if count_sieze(get_ua_list)==0 then return false end
	if get_ua_list then
		for __,v in pairs(get_ua_list)
		do
			if ngx.re.match(ua,v,'ijo') then
			    ngx.exit(config['cc']['status'])
			    return true 
			end
		end
	end
	return false
end

local function ThinkPHP_RCE5_0_23()
	if method == "POST" then
		ngx.req.read_body()
		data = ngx.req.get_post_args()
		if data==nil then return false end 
		if data['_method']  and data['method'] and data['server[REQUEST_METHOD]'] then
		    is_type='ThinkPHP攻击'
			lan_ip('post','拦截ThinkPHP 5.x RCE 攻击')
		end
		if data['_method']  and data['method'] and data['server[]'] and data['get[]'] then
		    is_type='ThinkPHP攻击'
			lan_ip('post','拦截ThinkPHP 5.x RCE 攻击,并且被封锁IP')
		end
		if type(data['_method'])=='string' then 
			if data['_method'] and ngx_match(data['_method'],'construct','ijo') then
				is_type='ThinkPHP攻击'
				lan_ip('post','拦截ThinkPHP 5.x RCE 攻击,并且被封锁IP')
			end
		end
		if type(data['_method'])=='table' then 
		    if not data['_method'] then return false end
			for _,_v2 in pairs(data['_method']) do 
				if type(_v2)=='string' then 
					if ngx_match(_v2,'construct','ijo') then 
						is_type='ThinkPHP攻击'
						lan_ip('post','拦截ThinkPHP 5.x RCE 攻击,并且被封锁IP')
					end 
				end 
			end 
		end
	end
	return false
end

local function ThinkPHP_3_log()
	if string.find(uri,'^/Application/.+log$') or string.find(uri,'^/Application/.+php$') or string.find(uri,'^/application/.+log$') or string.find(uri,'^/application/.+php$') then 
	    is_type='ThinkPHP攻击'
		lan_ip('args','拦截ThinkPHP 3.x 获取敏感信息操作,并且被封锁IP')
	end
	if string.find(uri,'^/Runtime/.+log$') or string.find(uri,'^/Runtime/.+php$')  or string.find(uri,'^/runtime/.+php$') or string.find(uri,'^/runtime/.+log$')then 
	    is_type='ThinkPHP攻击'
		lan_ip('args','拦截ThinkPHP 3.x 获取敏感信息操作,并且被封锁IP')
	end
	return false
end

local function error_transfer_encoding()
	if request_header['transfer-encoding'] == nil then return false end 
	if request_header['transfer-encoding'] then
	    is_type='GET参数'
		lan_ip('args','拦截 Transfer-Encoding 块请求,并且被封锁IP')
		return true
	else
		return false
	end
end

local function url_white_chekc()
   local char_string=config['url_white_chekc']
   if not char_string then return false end
   if arrlen(char_string) ==0 then return false end
   if arrlen(char_string) >=1 then 
       return char_string 
   end
end

local function url_white_chekc_data()
	local get_body=url_white_chekc()
	if get_body==false then return false end
	if request_uri==nil then return false end 
	url_data=split(request_uri,'?')
	if not url_data[1] then return false end
	if get_body and url_data[1] then
		for __,v in pairs(get_body)
		do
			if string.find(url_data[1],v) then 
				return true
			end
		end
	end
	return false
end

function string.split(str, delimiter)
	if str==nil or str=='' or delimiter==nil then
		return nil
	end
    local result = {}
    for match in (str..delimiter):gmatch("(.-)"..delimiter) do
        table.insert(result, match)
    end
    return result
end

function string.trim (s) return (string.gsub(s, "^%s*(.-)%s*$", "%1")) end
 
local function getUAField(t)
	local separator=';'
	local tab={}
	local android=string.find(t,"Android")
        local iphone=string.find(t,"Mac")
	local windows=string.find(t,"Windows")
 	if android  then
		tab["platform"]="android"
    		tab["ismobiledevice"]="true"
		local startIndex =string.find(t,"Build")
		if startIndex then
			local res=string.sub(t,0,startIndex-1)
			local rtable=string.split(res,separator)
			local devicename=string.trim(rtable[#rtable])
			local name=string.find(t,"XiaoMi")
			if name then
				local name1 = string.sub(t,name,name+6)
				tab["number"]=name
				if devicename~=nil then
					tab["devicename"]=name1 .. "/" .. devicename
				end
			else
				if devicename~=nil then
					tab["devicename"]=devicename
				end
			end
		end
 
		local osvTable=string.split(string.sub(t,android) ,separator)
		if osvTable then
			local osvTab=string.split(osvTable[1] ,' ')
			tab["os_version"]=string.trim(osvTab[#osvTab])
		end
	end
	if iphone then
		local ipho = string.find(t,"iPhone")
		local mac = string.find(t,"Macintosh")
		if ipho then
			tab["platform"]="iOS"
			tab["devicename"]="iphone"
			tab["number"]=ipho	
			tab["ismobiledevice"]="true"
 			local vs=string.find(t,"CPU")	
			if vs then
			    local osvTable=string.sub(t,vs)
			    local osvTable1 = string.split(osvTable,' ')
		            local osversion = string.trim(osvTable1[4])
			    tab["os_version"]=osversion
		        end	
		end
		if mac then
			tab["platform"]="Mac"
			tab["number"]=mac
			tab["devicename"]="PC"
			tab["ismobiledevice"]="flase"
			local osvers = string.sub(t,mac)
			local osversi= string.split(osvers,separator)
			if osversi then
				local osvTab = string.split(osversi[2],' ')
				table["os_version"]=string.trim(osvTab[5])
			end
		end
	end
    if windows  then
		tab["platform"]="Windows"
		tab["ismobiledevice"]="flase"
		local osvTable=string.split(string.sub(t,windows) ,separator)
		if osvTable then
			local osvTab=string.split(osvTable[1] ,' ')
			tab["os_version"]=string.trim(osvTab[#osvTab])
			tab["devicename"]="PC"
		end
	end
	if  next(tab)  == nil then
		tab["platform"]=""
		tab["devicename"]=""
		tab["os_version"]=""
		tab["number"]=""
		tab["ismobiledevice"]=""
	end
 
	return tab
end

local function send_Verification()
	local token = ngx.md5(ip)
	local count,_ = ngx.shared.btwaf:get(token)
	if count then
		if count > config['retry'] then
			local safe_count,_ = ngx.shared.drop_sum:get(ip)
			if not safe_count then
				ngx.shared.drop_sum:set(ip,1,86400)
				safe_count = 1
			else
				ngx.shared.drop_sum:incr(ip,1)
			end
			local lock_time = (config['retry_time'] * safe_count)
			if lock_time > 86400 then lock_time = 86400 end
			ngx.shared.drop_ip:set(ip,retry+1,lock_time)
			is_type='cc'
			lan_ip('cc','人机验证页面遭到该IP攻击:  '..config['retry_cycle']..'秒内累计超过'..config['retry']..'次请求,封锁' .. lock_time .. '秒')
		else
			ngx.shared.btwaf:incr(token,1)
		end
	else
		ngx.shared.btwaf:set(token,1,config['retry_cycle'])
	end

	if not request_header['user-agent'] then request_header['user-agent']='Mozilla/5.0 (Windows NT 10.0; Win64; x64)' end
	ua_type=getUAField(request_header['user-agent'])
	if ua_type["platform"] == "android" or ua_type["platform"]=="iOS" then 
		local jsbody= string.format([[
<html>
	<head>
		<title>宝塔防火墙</title>
		<style>
			body{font-family:Tahoma,Verdana,Arial,sans-serif;}.head_title{margin-top:0;font-family:"微软雅黑";font-size:50px;font-weight:lighter;}p{font-family:"微软雅黑";font-size:16px;font-weight:lighter;color:#666666;}.btn{width:90vw;height:11.5vw;line-height:11.5vw;text-align:center;font-size:4vw;background:#20a53a;box-shadow:inset 0 1px 2px #30ad42;color:#fff;text-shadow:#00851a 0 -1px 0;font-family:"微软雅黑";border:0;cursor:pointer;transition:all 500ms;margin-top:3vw;}.btn:hover{color:#fff;background-color:#008e1c;border-color:#398439;}.inp_captcha{float:left;padding:10px;width:58vw;box-sizing:border-box;padding-left:2vw;height:12vw;font-size:5vw;border:2px solid #c0c0c0;outline:none;border-right:0;}.inp_captcha:focus{border:2px solid #20a53a;border-right:0;padding-left:3vw;}.yzm{float:left;width:30vw;height:12vw;line-height:12vw;font-size:4vw;color:#333;border-radius:2px;border:2px solid #c0c0c0;box-sizing:border-box;}.form{margin:0 auto;overflow:hidden;margin-top:3.5vw;}.captcha-box{margin-top:20vw;padding:0 5vw;}#errmsg{font-size: 4vw;}
		</style>
	</head>
	<body>
		<script>
			if (window != top) {
				location.href = location.href
			}
		</script>
		<div align="center" class="captcha-box">
			<div class="tit">
				<img src="data:image/jpg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDACEXGR0ZFSEdGx0lIyEoMlM2Mi4uMmZJTTxTeWp/fXdqdHKFlr+ihY21kHJ0puOotcbM1tjWgaDr/OnQ+r/S1s7/2wBDASMlJTIsMmI2NmLOiXSJzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7/wAARCABwAIIDASIAAhEBAxEB/8QAGgAAAwEBAQEAAAAAAAAAAAAAAAQFAwIBBv/EADMQAAICAQIEAwYGAgMBAAAAAAECAAMRBCESMUFRBSJhEzJCcZGxM1KBodHhFPAjJcHx/8QAFAEBAAAAAAAAAAAAAAAAAAAAAP/EABQRAQAAAAAAAAAAAAAAAAAAAAD/2gAMAwEAAhEDEQA/AL8J4SAMk4HrAHIyIHsIQgZ3vwV7cztJekuZfEfYVklcniLHOZR1XJB6yX4e4XV6q3G4yB+p/qBbhJdeqdvEFqUux+PB2lSAQhFdZxZTDsq9eHrANdngC5IU8yDgxfw+8jU26YnIQAqT+/3mdOpsdH02oObU3VvzCcabbxkY+JN/p/UCzCEIBCE8DAnAIJgewhCBxagsrKnrJhsfTt7xCk7MOnoRK0SdFN71uMo/OB7VrOQtGx5MORjYIYZByD1kSxX0dxrbLIf3HeMUXmkgg8VZgO6oZrB7GTLSNKt1uPfbyDucSsXSyrPEOE9ZJ8QFvBV7M/Fw7dc//IDvhem9hpg7b2WeZj1jsRXWMiKpUMwABbuZ0ursY+6oHUmA5OXUOpU8jEv88tZYiqvEhwQeeO86GubrX+8DA0k3r+dCRnuJj4Xm7xG274VGB9h9ptqbW4HsBJyPKB35Ca+E0ijTYJHtGOWGeXpAfi92qVDwoON/TlMdTqS59nVy5EjrJWovZ3FFGTk4JHxHt8oDV+uZ2KBgzdce6vzjXhaE1Nc2TxnC57CTddUNHp69OPxH81h+w+Uu0IK6K0HwqBA0hCEAiWp2vyOwjsT1AHtSTvtygGupXUUKQQHG65ilVYrUqMv8+Qnuo1IpxnzWfCo6fOeDRajVgNY5pQ80x/5/MDi3U1VnzPxN2Xec16q21H9mmBkAADJlCnwzTVfBxnu+/wC0bVQowoAHYQI9dOssYAh1HcjEcFFgUKAcDucmOwgQ7tBrP8t7ql65B4hB6NcAGVbBnmuc4/qXIQIK26qtXFqnYZ8y4gmprYjJNbeu4+svRe3Rae736lz3GxgT289ZB5MMcS8/rPfDNIlWoNjOG28gOx9Z0/hb1Nxaa4gdVPP+IubSbPZ2qanHLPIwMfEX9r4oR0BCz6OfP20Cy0P7toYE55N/c+ggEIQgZ3W+yTPU8pN1Fz8fBQOOxjgn8v8Aveb6iwG1iT5UE48Kpyr6lx5nJx6CBto9Cmn87+e482PT5RyEIBCeT2AQhCAQhCAQhCATHUaavUpw2Lnseoms9gRGptot9jaOKv4bOw/3pG9Dqw1zaZua+6T1jWppF9LL15g+shWlq7K712I2/UQPo4TOu1HrVwRhgDzhAl32B6rAy9d8HGd5Q0WP8SvhGBjlELU4brEPXI/ia+F3jhNDHcbrApTi1uGtj6TuYatsU47mBlobstZSTupyPlGyQBkyRWGGv41OMAE/SMPYznzH9IDT6hF5eb5RXU+INUwVEUt1z0nLkpWXxnHLPeT2R2Yk4JPM5EB1PFLCcMib9dxOk8Yr4il9bVsDg43EQ9m3p9ROb6Hsr4wuXQb46iB9BVdXcvFU4cehhc/s6y3XpPla7HqYNWxVh1BlXT6t9XWBYRxod8dR3gO6Cwub0JyUf7gf3HJH8Lt/7HUJn3s/sZYgEg6pqwlpKZHHsOLrK+quFNRPxHYSDqzipF7kt/v7wNU1TitQFTAA6Qj9Phymmvi2PCM/SEDXW1lf+ZBuNie3rEXZ/wAStiCNyO3qJZIBBBGQZPt03srOME8H+7QPKddfYPcTbmxmer1b8aLsRjJXHOejcgAADoByE5pTjsbUNsPhz0HeBrgADAwzAcQ/8npITnue0Vu1XNaj82/id0/gJ+v3gds3FniwQdiDyiGq0fADZSMp1Xqv9R6AJByIEmmk2ZJPCg5t/EYyFAWscKjl3+Zmmo2tZQAFXkBsBMoA9a3noth69G+cypdtLqAzAjB8w7ib1/iL8xFltGOCwcSdO6/KA9Uwpv4qti5J4zvnM3XxS1lOEQsvvL1H9RGrZQhYMhPkfsex7TjU8SXCxcqW326HrAZfVW2k22WFVHb7Ce6FW1+pzYua0wc9vSY1VvryqJ5WXnt5fn85e02nTTUitOQ5nuYG0IQgE8IBGDuJ7CArZpBuUzgj3f4kvVW2FuBlNajksvTiytLBh1DD1gfPKpY4AzG6SppAVgxXZsdIzqPC0sXhqsasfl5gxJfDdZprOOrhfuAcZH6wN4AZnTqyV+0aqwD8oGTJuptvt8prZE/Lg/vA1vw1jOpDITsRymcxqN1beRW35jGQY5XRZcMpU6nqGG36GBnX74Y7Ku5J6ROytk3O6nkw5GUX0GruwiV8FY6scZPeMabwc1nNtxIPNVGx+sCNU7I3l3zsV5gyvX4e2rqRrQ1WDuDuSJRo0lGn/CqVT35n6zeBlRRXp6wlS8I+81hCAQhCB//Z" alt="" style="width:30vw;padding-bottom:10px"/>
			</div>
			<p style="font-weight: 400;font-size: 4.8vw;margin-bottom:1.5vw ">此为人机校验，请输入验证码继续访问</p>
			<p style="margin:0"><font color="red" id="errmsg"></font></p>
			<form class="form" action="#" onsubmit="return false" method="POST">
				<input id="value" class="inp_captcha" name="captcha" type="text" />
				<img class="yzm" id="yzm" onclick="showCaptcha()" alt="验证码图片">
				<button type="submit" class="btn" onclick="mfwaf_auth()" type="button">提交</button>
			</form>
		</div>
		<script>
			document.onkeydown=function(e){var theEvent=window.event||e;var code=theEvent.keyCode||theEvent.which||theEvent.charCode;if(code==13){var value=document.getElementById("value").value;var c="/Verification_auth_btwaf?captcha="+value;mfajax2("GET",c)}};function showCaptcha(){var t=(new Date()).valueOf();var b="/get_btwaf_captcha_base64?captcha="+t;mfajax("GET",b)}showCaptcha();function mfajax(a,b,c){var xmlHttp=new XMLHttpRequest();xmlHttp.onreadystatechange=function(){if(xmlHttp.readyState==4&&xmlHttp.status==200){var data=JSON.parse(xmlHttp.responseText);if(data.status==true){yzm.src="data:image/png;base64,"+data.msg}else{if(data.status){location.href=location.href}else{errmsg.innerHTML="验证码输入错误，请重新输入"}}}else{if(xmlHttp.readyState==4&&xmlHttp.status==404){if(a=="GET"){errmsg.innerHTML="无法获取验证码"}else{errmsg.innerHTML="此IP可能已经被屏蔽，请明天或稍后再试"}}}};xmlHttp.open(a,b,true);xmlHttp.send(c)}function mfajax2(a,b,c){var xmlHttp=new XMLHttpRequest();xmlHttp.onreadystatechange=function(){if(xmlHttp.readyState==4&&xmlHttp.status==200){var data=JSON.parse(xmlHttp.responseText);if(data.status==true){location.href=location.href}else{if(data.status){location.href=location.href}else{errmsg.innerHTML="验证码输入错误，请重新输入"}}}else{if(xmlHttp.readyState==4&&xmlHttp.status==404){if(a=="GET"){errmsg.innerHTML="无法获取验证码"}else{errmsg.innerHTML="此IP可能已经被屏蔽，请明天或稍后再试"}}}};xmlHttp.open(a,b,true);xmlHttp.send(c)}function mfwaf_auth(){var value=document.getElementById("value").value;var c="/Verification_auth_btwaf?captcha="+value;mfajax2("GET",c)};
		</script>
	</body>
	</html>
	]])
		ngx.header.content_type = "text/html;charset=utf8"
		ngx.header.Cache_Control = "no-cache"
		ngx.say(jsbody)
		ngx.exit(200)
	else
		local jsbody22 = string.format([[
	<html><head><title>宝塔防火墙</title>
	<style>body{font-family:Tahoma,Verdana,Arial,sans-serif}.head_title{margin-top:0;font-family:"微软雅黑";font-size:50px;font-weight:lighter}p{font-family:"微软雅黑";font-size:16px;font-weight:lighter;color:#666}.btn{float:left;width:63px;height:40px;background:#20a53a;box-shadow:inset 0 1px 2px #30ad42;color:#fff;text-shadow:#00851a 0 -1px 0;font-family:"微软雅黑";font-size:16px;border:0;cursor:pointer;outline:0;border-top-right-radius:2px;border-bottom-right-radius:2px;transition:all 500ms}.btn:hover{color:#fff;background-color:#008e1c;border-color:#398439}.inp_captcha{float:left;margin-left:10px;padding:10px;width:200px;height:40px;font-size:20px;border-top-left-radius:2px;border-bottom-left-radius:2px;border:1px solid #c0c0c0;outline:0;border-right:0}.inp_captcha:focus{border:1px solid #20a53a;border-right:0}.yzm{float:left;width:130px;height:40px;border-radius:2px}.form{margin:0 auto;width:415px;height:40px}</style>
	</head><body>
	<script>if (window != top) {location.href = location.href;}</script>
	<div align="center" class="captcha-box" style="margin-top:150px"><div class="tit">
	<img src="data:image/jpg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDACEXGR0ZFSEdGx0lIyEoMlM2Mi4uMmZJTTxTeWp/fXdqdHKFlr+ihY21kHJ0puOotcbM1tjWgaDr/OnQ+r/S1s7/2wBDASMlJTIsMmI2NmLOiXSJzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7/wAARCABwAIIDASIAAhEBAxEB/8QAGgAAAwEBAQEAAAAAAAAAAAAAAAQFAwIBBv/EADMQAAICAQIEAwYGAgMBAAAAAAECAAMRBCESMUFRBSJhEzJCcZGxM1KBodHhFPAjJcHx/8QAFAEBAAAAAAAAAAAAAAAAAAAAAP/EABQRAQAAAAAAAAAAAAAAAAAAAAD/2gAMAwEAAhEDEQA/AL8J4SAMk4HrAHIyIHsIQgZ3vwV7cztJekuZfEfYVklcniLHOZR1XJB6yX4e4XV6q3G4yB+p/qBbhJdeqdvEFqUux+PB2lSAQhFdZxZTDsq9eHrANdngC5IU8yDgxfw+8jU26YnIQAqT+/3mdOpsdH02oObU3VvzCcabbxkY+JN/p/UCzCEIBCE8DAnAIJgewhCBxagsrKnrJhsfTt7xCk7MOnoRK0SdFN71uMo/OB7VrOQtGx5MORjYIYZByD1kSxX0dxrbLIf3HeMUXmkgg8VZgO6oZrB7GTLSNKt1uPfbyDucSsXSyrPEOE9ZJ8QFvBV7M/Fw7dc//IDvhem9hpg7b2WeZj1jsRXWMiKpUMwABbuZ0ursY+6oHUmA5OXUOpU8jEv88tZYiqvEhwQeeO86GubrX+8DA0k3r+dCRnuJj4Xm7xG274VGB9h9ptqbW4HsBJyPKB35Ca+E0ijTYJHtGOWGeXpAfi92qVDwoON/TlMdTqS59nVy5EjrJWovZ3FFGTk4JHxHt8oDV+uZ2KBgzdce6vzjXhaE1Nc2TxnC57CTddUNHp69OPxH81h+w+Uu0IK6K0HwqBA0hCEAiWp2vyOwjsT1AHtSTvtygGupXUUKQQHG65ilVYrUqMv8+Qnuo1IpxnzWfCo6fOeDRajVgNY5pQ80x/5/MDi3U1VnzPxN2Xec16q21H9mmBkAADJlCnwzTVfBxnu+/wC0bVQowoAHYQI9dOssYAh1HcjEcFFgUKAcDucmOwgQ7tBrP8t7ql65B4hB6NcAGVbBnmuc4/qXIQIK26qtXFqnYZ8y4gmprYjJNbeu4+svRe3Rae736lz3GxgT289ZB5MMcS8/rPfDNIlWoNjOG28gOx9Z0/hb1Nxaa4gdVPP+IubSbPZ2qanHLPIwMfEX9r4oR0BCz6OfP20Cy0P7toYE55N/c+ggEIQgZ3W+yTPU8pN1Fz8fBQOOxjgn8v8Aveb6iwG1iT5UE48Kpyr6lx5nJx6CBto9Cmn87+e482PT5RyEIBCeT2AQhCAQhCAQhCATHUaavUpw2Lnseoms9gRGptot9jaOKv4bOw/3pG9Dqw1zaZua+6T1jWppF9LL15g+shWlq7K712I2/UQPo4TOu1HrVwRhgDzhAl32B6rAy9d8HGd5Q0WP8SvhGBjlELU4brEPXI/ia+F3jhNDHcbrApTi1uGtj6TuYatsU47mBlobstZSTupyPlGyQBkyRWGGv41OMAE/SMPYznzH9IDT6hF5eb5RXU+INUwVEUt1z0nLkpWXxnHLPeT2R2Yk4JPM5EB1PFLCcMib9dxOk8Yr4il9bVsDg43EQ9m3p9ROb6Hsr4wuXQb46iB9BVdXcvFU4cehhc/s6y3XpPla7HqYNWxVh1BlXT6t9XWBYRxod8dR3gO6Cwub0JyUf7gf3HJH8Lt/7HUJn3s/sZYgEg6pqwlpKZHHsOLrK+quFNRPxHYSDqzipF7kt/v7wNU1TitQFTAA6Qj9Phymmvi2PCM/SEDXW1lf+ZBuNie3rEXZ/wAStiCNyO3qJZIBBBGQZPt03srOME8H+7QPKddfYPcTbmxmer1b8aLsRjJXHOejcgAADoByE5pTjsbUNsPhz0HeBrgADAwzAcQ/8npITnue0Vu1XNaj82/id0/gJ+v3gds3FniwQdiDyiGq0fADZSMp1Xqv9R6AJByIEmmk2ZJPCg5t/EYyFAWscKjl3+Zmmo2tZQAFXkBsBMoA9a3noth69G+cypdtLqAzAjB8w7ib1/iL8xFltGOCwcSdO6/KA9Uwpv4qti5J4zvnM3XxS1lOEQsvvL1H9RGrZQhYMhPkfsex7TjU8SXCxcqW326HrAZfVW2k22WFVHb7Ce6FW1+pzYua0wc9vSY1VvryqJ5WXnt5fn85e02nTTUitOQ5nuYG0IQgE8IBGDuJ7CArZpBuUzgj3f4kvVW2FuBlNajksvTiytLBh1DD1gfPKpY4AzG6SppAVgxXZsdIzqPC0sXhqsasfl5gxJfDdZprOOrhfuAcZH6wN4AZnTqyV+0aqwD8oGTJuptvt8prZE/Lg/vA1vw1jOpDITsRymcxqN1beRW35jGQY5XRZcMpU6nqGG36GBnX74Y7Ku5J6ROytk3O6nkw5GUX0GruwiV8FY6scZPeMabwc1nNtxIPNVGx+sCNU7I3l3zsV5gyvX4e2rqRrQ1WDuDuSJRo0lGn/CqVT35n6zeBlRRXp6wlS8I+81hCAQhCB//Z" alt="" style="width:130px;padding-bottom:10px"/>
	</div>
	<p style="font-weight: 400;font-size: 17px">此为人机校验，请输入验证码来继续访问 (PS: 如需关闭此功能请在防火墙中关闭增强模式 )：</p><p><font color="red" id="errmsg"></font></p>
	<form class="form" action="#" onsubmit="return false" method="POST"><img class="yzm" id="yzm" onclick="showCaptcha()" alt="验证码图片"><input id="value" class="inp_captcha" name="captcha" type="text" /><button type="submit" class="btn" onclick="mfwaf_auth()" type="button">提交</button></form>
	</div>
	<script>document.onkeydown=function(e){var theEvent=window.event||e;var code=theEvent.keyCode||theEvent.which||theEvent.charCode;if(code==13){var value=document.getElementById("value").value;var c="/Verification_auth_btwaf?captcha="+value;mfajax2("GET",c)}};function showCaptcha(){var t=(new Date()).valueOf();var b="/get_btwaf_captcha_base64?captcha="+t;mfajax("GET",b)}showCaptcha();function mfajax(a,b,c){var xmlHttp=new XMLHttpRequest();xmlHttp.onreadystatechange=function(){if(xmlHttp.readyState==4&&xmlHttp.status==200){var data=JSON.parse(xmlHttp.responseText);if(data.status==true){yzm.src="data:image/png;base64,"+data.msg}else{if(data.status){location.href=location.href}else{errmsg.innerHTML="验证码输入错误，请重新输入"}}}else{if(xmlHttp.readyState==4&&xmlHttp.status==404){if(a=="GET"){errmsg.innerHTML="无法获取验证码"}else{errmsg.innerHTML="此IP可能已经被屏蔽，请明天或稍后再试"}}}};xmlHttp.open(a,b,true);xmlHttp.send(c)}function mfajax2(a,b,c){var xmlHttp=new XMLHttpRequest();xmlHttp.onreadystatechange=function(){if(xmlHttp.readyState==4&&xmlHttp.status==200){var data=JSON.parse(xmlHttp.responseText);if(data.status==true){location.href=location.href}else{if(data.status){location.href=location.href}else{errmsg.innerHTML="验证码输入错误，请重新输入"}}}else{if(xmlHttp.readyState==4&&xmlHttp.status==404){if(a=="GET"){errmsg.innerHTML="无法获取验证码"}else{errmsg.innerHTML="此IP可能已经被屏蔽，请明天或稍后再试"}}}};xmlHttp.open(a,b,true);xmlHttp.send(c)}function mfwaf_auth(){var value=document.getElementById("value").value;var c="/Verification_auth_btwaf?captcha="+value;mfajax2("GET",c)};</script>
	</body></html>
		]])
		ngx.header.content_type = "text/html;charset=utf8"
		ngx.header.Cache_Control = "no-cache"
		ngx.say(jsbody22)
		ngx.exit(200)
	 end
end 

local function getcookie()
    local data = request_header['cookie']
    local match_table = {}
    cookie_list=split2(data,';')
    if not cookie_list then return match_table end 
    for i,v in ipairs(cookie_list) do
        ret={}
        v_list=split2(v,'=')
        if arrlen(v_list)==1 then 
            match_table[v_list[1]]=''
        else
            v_list[1]=string.lower(string.gsub(v_list[1], " ", ""))
            if not match_table[v_list[1]] then 
                match_table[v_list[1]]={}
                table.insert(match_table[v_list[1]],ngx.unescape_uri(table.concat(v_list,' ',2)))
            else
                table.insert(match_table[v_list[1]],ngx.unescape_uri(table.concat(v_list,' ',2)))
            end 
        end 
    end 
    return match_table
end


local function send_Verification_renji(type)
    if type=='code' then 
        send_Verification()
    end 
    if type=='btwaf' then 
        local cache_token = ngx.md5(ip .. '_' .. server_name)
        send_check_heml(cache_token)
    end
	local token = ngx.md5(ip)
	local count,_ = ngx.shared.btwaf:get(token)
	if count then
		if count > config['retry'] then
			local safe_count,_ = ngx.shared.drop_sum:get(ip)
			if not safe_count then
				ngx.shared.drop_sum:set(ip,1,86400)
				safe_count = 1
			else
				ngx.shared.drop_sum:incr(ip,1)
			end
			local lock_time = (config['retry_time'] * safe_count)
			if lock_time > 86400 then lock_time = 86400 end
			ngx.shared.drop_ip:set(ip,retry+1,lock_time)
			bt_ip_filter(ip,lock_time)
			is_type='cc'
			lan_ip('cc','人机验证页面遭到该IP攻击:  '..config['retry_cycle']..'秒内累计超过'..config['retry']..'次请求,封锁' .. lock_time .. '秒')
		else
			ngx.shared.btwaf:incr(token,1)
		end
	else
		ngx.shared.btwaf:set(token,1,config['retry_cycle'])
	end
    if type=='renji' then
    	if not request_header['user-agent'] then request_header['user-agent']='Mozilla/5.0 (Windows NT 10.0; Win64; x64)' end
    	ua_type=getUAField(request_header['user-agent'])
    	if ua_type["platform"] == "android" or ua_type["platform"]=="iOS" then 
    		local jsbody = string.format([[
    <!DOCTYPE html><html>
      <head>
        <meta charset="UTF-8" />
        <title>人机验证</title>
        <meta name="viewport" content="width=device-width,initial-scale=1,minimum-scale=1,maximum-scale=1,user-scalable=no">
        <style>.verifyBox{position:fixed;top:0;right:0;bottom:0;left:0;text-align:center;white-space:nowrap;overflow:auto}.verifyBox:after{content:'';display:inline-block;height:100vh;vertical-align:middle}.verifyContent{display:inline-block;vertical-align:middle;text-align:center;white-space:normal}.loading{width:150px;height:15px;margin:0 auto;}.loading span{display:inline-block;width:15px;height:100%s;margin-right:5px;border-radius:50%s;background:#151515;-webkit-animation:load 1.5s ease infinite}.loading span:last-child{margin-right:0px}@-webkit-keyframes load{0%s{opacity:1}100%s{opacity:0}}.loading span:nth-child(1){-webkit-animation-delay:0.13s}.loading span:nth-child(2){-webkit-animation-delay:0.26s}.loading span:nth-child(3){-webkit-animation-delay:0.39s}.loading span:nth-child(4){-webkit-animation-delay:0.52s}.loading span:nth-child(5){-webkit-animation-delay:0.65s}h1{font-size:1.5em;color:#404040;text-align:center}</style>
      </head>
      <body>
      <div class="verifyBox">
        <div class="verifyContent">
            <div class="loading">
                <span></span>
                <span></span>
                <span></span>
                <span></span>
                <span></span>
            </div>
            <h1>宝塔防火墙正在检查您的访问</h1>
            <p id="bt-info">正在进行人机识别，请稍等……</p>
            <p>本站受宝塔防御系统保护</p>
        </div>
    </div>
        <script type="text/javascript" src="/renji_296d626f_%s.js?id=%s"></script>
      </body>
    </html>]],'%','%','%','%',ngx.md5(ip),os.time())
    		ngx.header.content_type = "text/html;charset=utf8"
    		ngx.header.Cache_Control = "no-cache"
    		ngx.say(jsbody)
    		ngx.exit(200)
    	else
    		local jsbody22 = string.format([[
    <!DOCTYPE html><html>
      <head>
        <meta charset="UTF-8" />
        <title>人机验证</title>
        <meta name="viewport" content="width=device-width,initial-scale=1,minimum-scale=1,maximum-scale=1,user-scalable=no">
        <style>.verifyBox{position:fixed;top:0;right:0;bottom:0;left:0;text-align:center;white-space:nowrap;overflow:auto}.verifyBox:after{content:'';display:inline-block;height:100vh;vertical-align:middle}.verifyContent{display:inline-block;vertical-align:middle;text-align:center;white-space:normal}.loading{width:150px;height:15px;margin:0 auto;}.loading span{display:inline-block;width:15px;height:100%s;margin-right:5px;border-radius:50%s;background:#151515;-webkit-animation:load 1.5s ease infinite}.loading span:last-child{margin-right:0px}@-webkit-keyframes load{0%s{opacity:1}100%s{opacity:0}}.loading span:nth-child(1){-webkit-animation-delay:0.13s}.loading span:nth-child(2){-webkit-animation-delay:0.26s}.loading span:nth-child(3){-webkit-animation-delay:0.39s}.loading span:nth-child(4){-webkit-animation-delay:0.52s}.loading span:nth-child(5){-webkit-animation-delay:0.65s}h1{font-size:1.5em;color:#404040;text-align:center}</style>
      </head>
      <body>
      <div class="verifyBox">
        <div class="verifyContent">
            <div class="loading">
                <span></span>
                <span></span>
                <span></span>
                <span></span>
                <span></span>
            </div>
            <h1>宝塔防火墙正在检查您的访问</h1>
            <p id="bt-info">正在进行人机识别，请稍等……</p>
            <p>本站受宝塔防御系统保护</p>
        </div>
    </div>
        <script type="text/javascript" src="/renji_296d626f_%s.js?id=%s"></script>
      </body>
    </html>]],'%','%','%','%',ngx.md5(ip),os.time())
    		ngx.header.content_type = "text/html;charset=utf8"
    		ngx.header.Cache_Control = "no-cache"
    		ngx.say(jsbody22)
    		ngx.exit(200)
    	end
    elseif type=='huadong' then 
        if not request_header['user-agent'] then request_header['user-agent']='Mozilla/5.0 (Windows NT 10.0; Win64; x64)' end
    	ua_type=getUAField(request_header['user-agent'])
    	if ua_type["platform"] == "android" or ua_type["platform"]=="iOS" then 
    		local jsbody= string.format([[
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width,initial-scale=1,minimum-scale=1,maximum-scale=1,user-scalable=no">
    <title>滑动验证</title>
    <style>.slideBox{position:fixed;top:0;right:0;bottom:0;left:0;text-align:center;font-size:0;white-space:nowrap;overflow:auto}.slideBox:after{content:'';display:inline-block;height:100vh;vertical-align:middle}.slider{display:inline-block;vertical-align:middle;text-align:center;font-size:13px;white-space:normal}.slider::before{content:'人机身份验证，请完成以下操作';font-size: 16px;display: inline-block;margin-bottom: 30px;}</style>
</head>
<body>
    <div class="slideBox"><div class="slider"></div></div>
    <script type="text/javascript" src="/huadong_296d626f_%s.js?id=%s"></script>
</body>
</html>]],ngx.md5(ip),os.time())
    		ngx.header.content_type = "text/html;charset=utf8"
    		ngx.say(jsbody)
    		ngx.exit(200)
    	else
    		local jsbody22 = string.format([[<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width,initial-scale=1,minimum-scale=1,maximum-scale=1,user-scalable=no">
    <title>滑动验证</title>
    <style>.slideBox{position:fixed;top:0;right:0;bottom:0;left:0;text-align:center;font-size:0;white-space:nowrap;overflow:auto}.slideBox:after{content:'';display:inline-block;height:100vh;vertical-align:middle}.slider{display:inline-block;vertical-align:middle;text-align:center;font-size:13px;white-space:normal}.slider::before{content:'人机身份验证，请完成以下操作';font-size: 16px;display: inline-block;margin-bottom: 30px;}</style>
</head>
<body>
    <div class="slideBox"><div class="slider"></div></div>
    <script type="text/javascript" src="/huadong_296d626f_%s.js?id=%s"></script>
</body>
</html>]],ngx.md5(ip),os.time())
    		ngx.header.content_type = "text/html;charset=utf8"
    		ngx.header.Cache_Control = "no-cache"
    		ngx.say(jsbody22)
    		ngx.exit(200)
    	end
        
	end 
end 

local function renji(type)
	if not config['cc']['open'] or not site_cc then return false end
	if not site_config[server_name] then return false end
	if not site_config[server_name]['cc']['increase'] then return false end
	if ngx_match(uri,"\\.(css|js|png|gif|ico|jpg|jpeg|bmp|flush|swf|pdf|rar|gz|zip|doc|docx|xlsx|ts|sh|tiff|avi|mp3|mp4|xls|wav|exe|map|bak|tmp|dot|psd|txt|c|cpp|java|ico|dll|bat)$","isjo") then return false end
	cookie_list=getcookie()
	local token=''
	if request_header['user-agent']~=nil then 
		token=ngx.md5(ip..request_header['user-agent']..server_name..type..today)
	else
		token=ngx.md5(ip..server_name..type..today)
	end 
	cac_token=ngx.shared.btwaf:get(token)
	if not cac_token or cac_token==nil then 
	    send_Verification_renji(type)
	end 
	if cookie_list[token] then 
	    if type=='btwaf' then 
	       if not security_verification() then 
                send_Verification_renji(type)
	       end 
	       return false
	    end 
	    for i,k in pairs(cookie_list[token]) do 
	       if k==cac_token then
	           return false
	       end
	    end
	end
    ngx.shared.btwaf:delete(token)
    send_Verification_renji(type)
end


local function renji_cc(type)
	if not config['cc']['open'] or not site_cc then return false end
	if not site_config[server_name] then return false end
	cookie_list=getcookie()
	token=ngx.md5(ip..request_header['user-agent']..server_name..type..today)
	cac_token=ngx.shared.btwaf:get(token)
	if not cac_token or cac_token==nil then 
	    send_Verification_renji(type)
	end 
	if cookie_list[token] then 
	    for i,k in pairs(cookie_list[token]) do 
	       if k==cac_token then
	           return false
	       end
	    end
	end
    token=ngx.md5(ip..request_header['user-agent']..server_name..type..today)
    ngx.shared.btwaf:delete(token)
    send_Verification_renji(type)
end


local function cc3()
	if not config['cc']['open'] or not site_cc then return false end
	if not site_config[server_name] then return false end
	if  request_header['user-agent']==nil then return false end
--	if not site_config[server_name]['cc']['increase'] then return false end 
    if cc_uri_white() then return false end 
	if not site_config[server_name]['cc']['increase'] then 
        if  config['url_cc_param']~=nil and uri_check[1] then 
            for k,v in pairs(config['url_cc_param']) do 
                if v['stype']=='regular' then 
                    if ngx.re.match(uri_check[1],k) then 
                        local param_count=arrlen(v['param'])
                        if param_count>=1 and count_sieze(uri_request_args)>=1 then 
                           local count =0
                            for _,v2 in ipairs(v['param']) do 
                                if uri_request_args[v2] then 
                                    count=count+1
                                end 
                            end
                            if count==param_count then 
                                if v['type']==1 then 
                                renji_cc("btwaf")
                                elseif v['type']==2 then 
                                    renji_cc("code")
                                elseif v['type']==3 then 
                                    renji_cc("renji")
                                elseif v['type']==4 then 
                                    renji_cc("huadong")
                                end
                            end 
                        elseif param_count==0 then 
                            if v['type']==1 then 
                                renji_cc("btwaf")
                            elseif v['type']==2 then 
                                renji_cc("code")
                            elseif v['type']==3 then 
                                renji_cc("renji")
                            elseif v['type']==4 then 
                                renji_cc("huadong")
                            end
                        end
                    end 
                else
                    if k == uri_check[1] then 
                        local param_count=arrlen(v['param'])
                        if param_count>=1 and count_sieze(uri_request_args)>=1 then 
                            local count =0
                            for _,v2 in ipairs(v['param']) do 
                                if uri_request_args[v2] then 
                                    count=count+1
                                end 
                            end
                            if count==param_count then 
                                if v['type']==1 then 
                                renji_cc("btwaf")
                                elseif v['type']==2 then 
                                    renji_cc("code")
                                elseif v['type']==3 then 
                                    renji_cc("renji")
                                elseif v['type']==4 then 
                                    renji_cc("huadong")
                                end
                            end 
                        else
                            if v['type']==1 then 
                                renji_cc("btwaf")
                            elseif v['type']==2 then 
                                renji_cc("code")
                            elseif v['type']==3 then 
                                renji_cc("renji")
                            elseif v['type']==4 then 
                                renji_cc("huadong")
                            end
                        end 
                    end 
                end
            end 
        end 
	end
	if site_config[server_name]['cc']['cc_increase_type']=='code' then 
		renji("code")
	elseif site_config[server_name]['cc']['cc_increase_type']=='renji' then 
		renji("renji")
	elseif site_config[server_name]['cc']['cc_increase_type']=='huadong' then 
		renji("huadong")
	else 
		renji("btwaf")
	end
end


local function  return_error3(method,msg)
	error_rule = msg
	write_log(method,msg)
end 

local function method_type_check(method)
    if not config['method_type'] then 
        return true
    else
        method_type=config['method_type']
    end
    for i,v in ipairs(method_type) do
        if method == v[1] and v[2] then 
            return true 
        end
    end 
    return false 
end 

local function header_check(header_data,len_data,header)
    for i,v in pairs(header_data) do
            if header == v[1] then 
                 if tonumber(len_data)>tonumber(v[2]) then return true end 
                 return false
            end
    end 
   	if len_data>20000 then return true end
    return false
end 



local function header_len_check(request_header)
	if method=='PROPFIND' or  method=='PROPPATCH' or method=='MKCOL' or method=='CONNECT'  or method=='SRARCH' then return false end
    if not  method_type_check(method) then
    	return_error3(method,'宝塔WAF提醒您不允许您当前的请求类型'..method..'此请求类型已经被禁用。如需开启请在Nginx防火墙-->全局设置-->HTTP请求过滤-->请求类型过滤开启'..method..'请求') 
    	return_html_data('网站防火墙','宝塔WAF提醒您不允许您当前的请求类型','宝塔WAF提醒您不允许您当前的请求类型','Nginx防火墙-->全局设置-->HTTP请求过滤-->请求类型过滤开启'..method..'请求')
    end
    if not request_header then  
    	return_error3(method,'宝塔WAF提醒您header获取失败,可能是头部请求太长,如有误报.请调整nginx的header获取大小')
    	return_html_data('网站防火墙','网站防火墙提醒您header获取失败','网站防火墙提醒您header获取失败','调整nginx的header获取大小')
    end
    if not  config['header_len'] then
        return false
    else
        header_data=config['header_len']
    end 
    for i,v in pairs(request_header) do
      if  header_check(header_data,#v,i) then  
		if i=='cookie' or i=='user-agent' then return false end 
     	return_error3(method,'网站防火墙提醒您header头部参数'..i..'太长，如有误报请在Nginx防火墙--全局设置--HTTP请求过滤--请求头过滤调整'..i..'的长度,如果没有这个'..i..'的选项需要添加建议把长度默认为10000')
      	return_html_data('网站防火墙','网站防火墙提醒您header头部参数'..i..'太长','网站防火墙提醒您header头部参数'..i..'太长','Nginx防火墙-->全局设置-->HTTP请求过滤-->请求头过滤调整'..i..'的长度。如果没有这个'..i..'的选项需要添加建议把长度默认为10000')
      end
    end
end



local function php_path()
	if site_config[server_name] == nil then return false end
	for _,rule in ipairs(site_config[server_name]['disable_php_path'])
	do
	   -- url_data=split2(request_uri,'?')
        if not url_data then url_data=request_uri end 
        if not url_data[1] then 
            url_data=request_uri 
        else
            url_data=url_data[1]
        end
		if ngx_match(url_data,rule .. "/?.*\\.php$","isjo") then
		    is_type='目录防护'
			write_log('disable_php_path','Nginx网站防火墙提醒您:当前目录禁止执行PHP文件,如有误报请在Nginx防火墙--站点配置--设置--禁止运行PHP的URL删除当前目录')
			return_html_data('当前目录禁止执行PHP文件','当前目录禁止执行PHP文件','您当前目录设置了禁止访问PHP文件','Nginx防火墙--站点配置--设置--禁止运行PHP的URL删除当前目录')
		end
	end
	return false
end


local function ua_whilie2(ua)
	if not ua then return false end 
	ua = string.lower(ua)
    if ngx.re.match(ua,'baiduspider') then return true end 
    if ngx.re.match(ua,'googlebot') then return true end 
    if ngx.re.match(ua,'360spider') then return true end 
    if ngx.re.match(ua,'sogou') then return true end 
    if ngx.re.match(ua,'yahoo') then return true end 
    if ngx.re.match(ua,'bingbot') then return true end 
    if ngx.re.match(ua,'yisouspider') then return true end 
	if ngx.re.match(ua,'haosouspider') then return true end 
	if ngx.re.match(ua,'sosospider') then return true end 
	if ngx.re.match(ua,'weixin') then return true end 
	if ngx.re.match(ua,'iphone') then return true end
	if ngx.re.match(ua,'android') then return true end 
end 

local function header_lan(header)
    if not config['is_browser'] then return false end 
    if type(header['connection'])~='string' then return false end 
    if ua_whilie2(request_header['user-agent']) then return false end
    if is_ssl() then return false end
    if header['connection'] =='close' then 
        if method =='GET' then method='args' end 
        if method =='POST' then method ='post' end 
        is_type='非浏览器请求'
        write_log(method,'非浏览器请求已被系统拦截,如想关闭此功能如下操作:Nginx防火墙--全局设置--非浏览器拦截')
	    ngx.exit(200)
    end
end


local function is_check_header()
    is_check_headers=ngx.req.get_headers(2000)
    count=0
	if type(is_check_headers)=='table' then
		for _,v in pairs(is_check_headers)
		do
			if type(v)=='table' then
				for k2,v2 in pairs(v) do 
				   count=count+1 
				end 
			else
			  count=count+1 
			end
		end
	end
	if count>800 then 
	    return lan_ip('post','header字段大于800 被系统拦截') 
	end 
end

function run_btwaf()
	server_name = get_server_name_waf()
	if not config['open'] or not is_site_config('open') then return false end
	error_rule = nil
	request_uri = ngx.var.request_uri
	uri = ngx.unescape_uri(ngx.var.uri)
	url_data=split2(request_uri,'?')
	method = ngx.req.get_method()
	request_header = ngx.req.get_headers(20000)
	ip = get_client_ip_bylog()
	ipn = arrip(ip)
	ipn2 = ip2long(ip)
	uri_request_args = ngx.req.get_uri_args(100000)
	cycle = config['cc']['cycle']
	endtime = config['cc']['endtime']
	limit = config['cc']['limit']
	retry = config['retry']
	retry_time = config['retry_time']
	retry_cycle = config['retry_cycle']
	min_route()
	site_cc = is_site_config('cc')
	if site_config[server_name] and site_cc then
		cycle = site_config[server_name]['cc']['cycle']
		endtime = site_config[server_name]['cc']['endtime']
		limit = site_config[server_name]['cc']['limit']
	end
	if site_config[server_name] then
		retry = site_config[server_name]['retry']
		retry_time = site_config[server_name]['retry_time']
		retry_cycle = site_config[server_name]['retry_cycle']
	end
	if ip_white() then return true end 
	is_check_header()
	drop()
	ip_black()
	if ua_white() then return true end
	ua_black()
	btwaf_init_db()
	if  ngx.shared.spider:get(ip) then 
        args()
		post()
		post_data()
		post_data_chekc()
		return false
	end
	local reptile_id=reptile_entrance(request_header['user-agent'],ip)
    if reptile_id==2 then
        args()
		post()
		post_data()
		post_data_chekc()
		return false
    end
	url_find(request_uri)
	header_len_check(request_header)
	if url_white_chekc_data() then 
		cc()
		args()
		post()
		post_data()
	else
		if url_white() then return true end
		url_black()
		drop_abroad()
		drop_china()
		header_lan(request_header)
		user_agent()
		cc()
		set_inser_cc()
		cc3()
		url()
        cookie()
	    args()
		scan_black()
	    if ThinkPHP_RCE5_0_23() then return true end
		if ThinkPHP_3_log() then return true end
		if error_transfer_encoding() then return true end
		post()
		post_data()
		post_data_chekc()
		if site_config[server_name] then
			X_Forwarded()
			php_path()
			url_path()
			url_ext()
			url_rule_ex()
			url_tell()
		end
	end
end 
