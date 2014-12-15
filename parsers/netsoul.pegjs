start
  = command

command
  = d:rep_command   {return {type: "rep", data:d}; }
  / d:ping_command  {return {type: "ping", data:d}; }
  / d:salut_command {return {type: "salut", data:d}; }
  / d:user_command  {return {type: "user_cmd", data:d}; }

rep_command
  = "rep " code:int " -- " text:random_data {return {code: code, text: text}; }

ping_command
  = "ping " time:int {return {timestamp: time}; }

salut_command
  = "salut " sock:int " " hash:md5_hash " " ip:ip_addr " " port:int " " time:int  {return {socket: sock, hash: hash, ip: ip, port: port, timestamp: time}; }

user_command
  = "user_cmd " sock:int ":user:" low:int "/" high:int ":" login:login "@" ip:ip_addr ":" work:no_space ":" loc:encoded ":" group:no_space " | " cmd:user_command_cmd {return {socket: sock, trust_level_low: low, trust_level_high: high, login: login, ip: ip, workstation_type: work, location: loc, group: group, cmd: cmd}; }

user_command_cmd
  = "login" {return {type: "login"}; }
  / "logout" {return {type: "logout"}; }
  / "who " d:user_command_who {return {type: "who", data: d}; }
  / "who rep 002 -- cmd end" {return {type: "who_end"}; }
  / "state " state:state {return {type: "state", data: state}; }
  / cmd:no_space " " data:encoded " dst=" dests:dests {return {type: "other", data: {cmd: cmd, data: data, dests: dests}}; }

user_command_who
  = sock:int " " login:login " " ip:ip_addr " " log_time:int " " chg_time:int " " low:int " " high:int " " work:no_space " " loc:encoded " " group:no_space " " state:state " " res:encoded { return {socket:sock, login: login, ip: ip, login_timestamp: log_time, last_change_timestamp: chg_time, trust_level_low: low, trust_level_high: high, workstation_type: work, location: loc, group: group, state: state, resource: res}; }

dests
  = "{" logins:dests_logins "}" { return logins; }
  / dests_login

dests_logins
  = login:dests_login "," logins:dests_logins { return [login].concat(logins); }
  / login:dests_login                         { return [login]; }

dests_login
  = ":" nb:int  { return nb; }
  / login

ip_addr
  = $([0-9]+ "." [0-9]+ "." [0-9]+ "." [0-9]+)

md5_hash
  = $[0-9a-fA-F]+

int
  = nb:$[0-9]+  { return parseInt(nb, 10); }

encoded
  = data:no_space { return decodeURIComponent(data); }

no_space
  = $[^ :]+

random_data
  = $.+

login
  = $[a-zA-Z_]+

state
  = state:$[a-zA-z]+ ":" time:int  {return {state: state, timestamp: time}; }
  / state:$[a-zA-z]+ {return {state: state}; }
