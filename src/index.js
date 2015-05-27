"use strict"
var os = require("os"),
  crypto = require("crypto"),
  _ = require("lodash"),
  P = require("bluebird"),
  Duplex = require("readable-stream/duplex"),
  util = require("util")

var DEFAULT_OPTS = {
  location: os.hostname() || "netsoul-protocol",
  resource: "netsoul-protocol",
  autoPing: true,
  lineDelim: /\r?\n/
}

function makeLoginList(logins) {
  switch (typeof logins) {
    case "string": return logins
    case "number": return ":" + logins
    default:
      return ["{", _.map(logins, function(login) {
        switch(typeof login) {
          case "number": return ":" + login
          case "string": return login
          default: return ""
        }
      }), "}"].join("")
  }
}

function parseLoginList(str) {
  var logins = function() {
    if (str.startsWith("{") && str.endsWith("}")) {
      return str.slice(1, -1).split(",")
    }
    return [str]
  }
  return _.map(logins(), function(login) {
    if (login.startsWith(":")) return parseInt(login.slice(1))
    return login
  })
}

function NSClient(opts) {
  if (!(this instanceof NSClient)) return new NSClient(opts)
  NSClient.super_.call(this)

  opts = _.pick(opts, _.keys(DEFAULT_OPTS))
  this._opts = opts = _.extend(DEFAULT_OPTS, opts)
  this._userCmdCustom = {
    msg: this._onCmdMsg,
    dotnetSoul_UserTyping: this._onCmdTyping,
    dotnetSoul_UserCancelledTyping: this._onCmdCancelledTyping,
    file_ask: this._onCmdFileAsk,
    file_start: this._onCmdFileStart
  }
  if (opts.autoPing) {
    this.on("ping", this.sendPing)
  }
}

util.inherits(NSClient, Duplex)

NSClient.NS_HOST = "ns-server.epita.fr"
NSClient.NS_PORT = 4242

NSClient.prototype._buffer = ""
NSClient.prototype._outBuffer = ""
NSClient.prototype._repQueue = []
NSClient.prototype._whoQueue = []
NSClient.prototype._whoBuffer = []
NSClient.prototype._salutData = null
NSClient.prototype.info = {}

NSClient.prototype._createRepPromise = function() {
  var D = P.defer()
  this._repQueue.push(D)
  return D.promise
}

NSClient.prototype._read = function(size) {}

NSClient.prototype._write = function(chunk, enc, next) {
  var matches = (this._buffer + chunk.toString()).split(this._opts.lineDelim)
  this._buffer = matches.pop()
  _.forEach(matches, function(line) {
    this.emit("line", line)
    var words = line.split(" ")
    if (words.length > 0) {
      switch (words[0]) {
        case "rep": return this._onRep(words)
        case "ping": return this._onPing(words)
        case "salut": return this._onSalut(words)
        case "user_cmd": return this._onUserCmd(words)
        default: return this.emit("unknownLine", words)
      }
    }
  }, this)
  next()
}

// Methods

NSClient.prototype.pushLine = function(line) {
  this.emit("pushLine", line)
  this.push(line + "\n")
}

NSClient.prototype.sendExit = function() {
  this.pushLine("exit")
}

NSClient.prototype.sendPing = function(time) {
  this.pushLine("ping " + time)
}

NSClient.prototype.sendState = function(state, time) {
  time = time || Date.now() / 1000
  this.pushLine(["state ", state, ":", parseInt(time)].join(""))
}

NSClient.prototype.sendWatch = function(logins) {
  this.pushLine("user_cmd watch_log_user " + makeLoginList(logins))
}

NSClient.prototype.sendCmdUser = function(cmd, dt, ds) {
  this.pushLine([
    "user_cmd msg_user",
    makeLoginList(ds),
    cmd,
    encodeURIComponent(dt)
  ].join(" "))
}

NSClient.prototype.sendMsg = function(msg, dests) {
  this.sendCmdUser("msg", msg, dests)
}

NSClient.prototype.sendTyping = function(dests) {
  this.sendCmdUser("dotnetSoul_UserTyping", "null", dests)
}

NSClient.prototype.sendCancelledTyping = function(dests) {
  this.sendCmdUser("dotnetSoul_UserCancelledTyping", "null", dests)
}

NSClient.prototype.sendFileAsk = function(name, size, desc, dests) {
  this.sendCmdUser("file_ask", [
    encodeURIComponent(name),
    size,
    encodeURIComponent(desc),
    "passive"
  ].join(" "), dests)
}

NSClient.prototype.sendFileStart = function(name, ip, port, dests) {
  this.sendCmdUser(
    "file_start",
    [encodeURIComponent(name), ip, port].join(" "),
    dests
  )
}

NSClient.prototype.sendAuthAg = function() {
  this.pushLine("auth_ag ext_user none none")
  return this._createRepPromise()
}

NSClient.prototype.sendExtUserLog = function(login, hash) {
  var enc = encodeURIComponent,
    o = this._opts
  this.pushLine(
    ["ext_user_log", login, hash, enc(o.location), enc(o.resource)].join(" ")
  )
  return this._createRepPromise()
}

NSClient.prototype.sendWho = function(logins) {
  logins = (typeof(logins) == "string") ? [logins] : logins
  this.pushLine("user_cmd who " + makeLoginList(logins))
  var D = P.defer()
  this._whoQueue.push({
    defer: D,
    logins: logins
  })
  return D.promise
}

NSClient.prototype.doAuthentication = function(login, passwd) {
  if (this._salutData === undefined) return P.reject("salut never happened")
  var data = this._salutData,
    salutHash = crypto.createHash("md5")
  salutHash.update([data.hash, "-", data.ip, "/", data.port, passwd].join(""))
  salutHash = salutHash.digest("hex")
  return this.sendAuthAg().bind(this).then(function(res) {
    if (res.code == 2) return this.sendExtUserLog(login, salutHash)
    return P.reject("Can't ask authentication.")
  }).then(function(res) {
    if (res.code != 2) return P.reject("Authentication failed.")
  })
}

// Netsoul default handling

NSClient.prototype._onRep = function(words) {
  var data = {
    code: parseInt(words[1]),
    text: words.slice(2).join(" ")
  },  D = this._repQueue.shift()
  this.emit("rep", data.code, data.text)
  if (D !== undefined) return D.resolve(data)
  this.emit("unexpectedRep", data.code, data.text)
}

NSClient.prototype._onPing = function(words) {
  this.emit("ping", parseInt(words[1]))
}

NSClient.prototype._onSalut = function(words) {
  this._salutData = {
    socket: parseInt(words[1]),
    hash: words[2],
    ip: words[3],
    port: parseInt(words[4]),
    timestamp: parseInt(words[5])
  }
  this.info = _.pick(this._salutData, "socket", "ip", "port")
  this.emit("salut", this._salutData)
}

NSClient.prototype._onUserCmd = function(words) {
  var tmp = words[1].split(":"),
    trust_levels = tmp[2].split("/"),
    user_data = tmp[3].split("@"),
    cmd = words.slice(3),
    data = {
      socket: parseInt(tmp[0]),
      trust_level_low: parseInt(trust_levels[0]),
      trust_level_high: parseInt(trust_levels[1]),
      login: user_data[0],
      ip: user_data[1],
      workstation_type: tmp[4],
      location: decodeURIComponent(tmp[5]),
      group: tmp[6]
    }
  this.emit("userCmd", data, cmd)
  switch (cmd[0]) {
    case "login": return this._onCmdLogin(data)
    case "logout": return this._onCmdLogout(data)
    case "who": return this._onWho(data, cmd)
    case "state": return this._onCmdState(data, cmd)
    default:
      if (cmd.length == 3 && cmd[2].startsWith("dst=")) {
        this._onCmdOther(data, cmd)
      } else {
        this.emit("unknownUserCmd", data, cmd)
      }
  }
}

// Netsoul original user_cmd handling

NSClient.prototype._onCmdWho = function(sender, data) {
  if (data[1] == "rep") {
    var who = this._whoQueue.shift(),
      whoBuffer = this._whoBuffer
    this._whoBuffer = []
    if (who === undefined) {
      return this.emit("unexpectedUserCmdWhoEnd", whoBuffer)
    }
    var whoResult = {
      logins: who.logins,
      result: whoBuffer
    }
    this.emit("userCmdWhoEnd", sender, whoResult)
    who.defer.resolve(whoResult)
  } else {
    var state = data[11].split(":"),
        whoData = {
          socket: parseInt(data[1]),
          login: data[2],
          ip: data[3],
          login_timestamp: parseInt(data[4]),
          last_change_timestamp: parseInt(data[5]),
          trust_level_low: parseInt(data[6]),
          trust_level_high: parseInt(data[7]),
          workstation_type: data[8],
          location: decodeURIComponent(data[9]),
          group: data[10],
          state: {
            state: state[0],
            timestamp: parseInt(state[1])
          },
          resource: decodeURIComponent(data[12])
        }
    this.emit("userCmdWho", sender, whoData)
    this._whoBuffer.push(whoData)
  }
}

NSClient.prototype._onCmdState = function(sender, data) {
  var tmp = data[1].split(":")
  this.emit("userCmdState", sender, {
    state: tmp[0],
    timestamp: parseInt(tmp[1])
  })
}

NSClient.prototype._onCmdLogin = function(sender) {
  this.emit("userCmdLogin", sender)
}

NSClient.prototype._onCmdLogout = function(sender) {
  this.emit("userCmdLogout", sender)
}

NSClient.prototype._onCmdOther = function(sender, data) {
  var oData = {
    cmd: data[0],
    data: decodeURIComponent(data[1]),
    dests: parseLoginList(data[2].slice(4))
  },  fn = this._userCmdCustom[oData.cmd]
  this.emit("userCmdOther", sender, oData)
  if (fn !== undefined) return fn(sender, oData.data, oData.dests)
  this.emit("userCmdCustom", sender, oData)
}

// Netsoul other user_cmd handling

NSClient.prototype._onCmdMsg = function(sender, data, dests) {
  this.emit("userCmdMsg", sender, data, dests)
}

NSClient.prototype._onCmdTyping = function(sender, data, dests) {
  this.emit("userCmdTyping", sender, dests)
}

NSClient.prototype._onCmdCancelledTyping = function(sender, data, dests) {
  this.emit("userCmdCancelledTyping", sender, dests)
}

NSClient.prototype._onCmdFileAsk = function(sender, data, dests) {
  var tmp = data.split(" ")
  if (tmp.length == 4) {
    this.emit("userCmdFileAsk", sender, {
      name: decodeURIComponent(tmp[0]),
      size: parseInt(tmp[1]),
      desc: decodeURIComponent(tmp[2]),
      method: tmp[3]
    }, dests)
  }
}

NSClient.prototype._onCmdFileStart = function(sender, data, dests) {
  var tmp = data.split(" ")
  if (tmp.length == 3) {
    this.emit("userCmdFileAsk", sender, {
      name: decodeURIComponent(tmp[0]),
      ip: parseInt(tmp[1]),
      port: decodeURIComponent(tmp[2])
    }, dests)
  }
}

module.exports = NSClient
