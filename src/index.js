var util = require("util")
  , os = require("os")
  , crypto = require("crypto")
  , _ = require("lodash")
  , Q = require("q")
  , through = require("through2")

var DEFAULT_OPTS = {
  location: os.hostname() || "netsoul-protocol",
  resource: "netsoul-protocol",
  autoPing: true,
  lineDelim: /\r?\n/
}

var ThroughConstructor = through.ctor(function(chunk, enc, cb) {
  var self = this
    , matches = (this._buffer + chunk.toString()).split(this._opts.lineDelim)
  this._buffer = matches.pop()
  _.forEach(matches, function(line) {
    self.emit("line", line)
    var words = line.split(" ")
    if (words.length <= 0) return
    switch (words[0]) {
      case "rep": self._onRep(words); break
      case "ping": self._onPing(words); break
      case "salut": self._onSalut(words); break
      case "user_cmd": self._onUserCmd(words); break
      default: self._onUnknown(words)
    }
  })
  cb()
})

function NSClient(opts) {
  ThroughConstructor.call(this) // call ThroughConstructor

  opts = _.pick(opts, _.keys(DEFAULT_OPTS))
  this._opts = opts = _.extend(DEFAULT_OPTS, opts)
  this._buffer = String() // Data buffer
  this._repQueue = [] // Waitings response
  this._whoQueue = [] // Waitings who response
  this._whoBuffer = [] // Who tmp buffer
  this._salutData = undefined
  this._userCmdCustom = {
    msg: this._onCmdMsg,
    dotnetSoul_UserTyping: this._onCmdTyping,
    dotnetSoul_UserCancelledTyping: this._onCmdCancelledTyping,
    file_ask: this._onCmdFileAsk,
    file_start: this._onCmdFileStart
  }
  this.info = {}

  if (this._opts.autoPing) {
    this.on("ping", this.sendPing)
  }
}

util.inherits(NSClient, ThroughConstructor)

// Static methods

NSClient.makeLoginList = function makeLoginList(logins) {
  if (typeof logins == "string") return logins
  if (typeof logins == "number") return ":" + logins
  return "{" + _.map(logins, function(login) {
    switch (typeof login) {
      case "number": return ":" + login
      case "string": return login
      default: return ""
    }
  }) + "}"
}

NSClient.parseLoginList = function parseLoginList(str) {
  var logins = undefined
  if (str.startsWith("{") && str.endsWith("}")) {
    logins = str.slice(1, -1).split(",")
  } else {
    logins = [str]
  }
  return _.map(logins, function(login) {
    if (login.startsWith(":")) {
      return parseInt(login.slice(1))
    }
    return login
  })
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
  this.pushLine(`ping ${time}`)
}

NSClient.prototype.sendState = function(state, time) {
  time = parseInt(time || parseInt(Date.now() / 1000))
  this.pushLine(`state ${state}:${time}`)
}

NSClient.prototype.sendWatch = function(logins) {
  this.pushLine("user_cmd watch_log_user " + makeLoginList(logins))
}

NSClient.prototype.sendCmdUser = function(cmd, data, dests) {
  if (cmd != undefined && data != undefined && dests != undefined) {
    this.pushLine(`user_cmd msg_user ${makeLoginList(dests)} ${cmd} ${encodeURIComponent(data)}`)
  }
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
  this.sendCmdUser("file_ask", `${encodeURIComponent(name)} ${size} ${encodeURIComponent(desc)} passive`, dests)
}

NSClient.prototype.sendFileStart = function(name, ip, port, dests) {
  this.sendCmdUser("file_start", `${encodeURIComponent(name)} ${ip} ${port}`, dests)
}

NSClient.prototype.sendAuthAg = function() {
  this.pushLine("auth_ag ext_user none none")
  return this._createRepPromise()
}

NSClient.prototype.sendExtUserLog = function(login, hash) {
  this.pushLine(`ext_user_log ${login} ${hash} ${encodeURIComponent(this._opts.location)} ${encodeURIComponent(this._opts.resource)}`)
  return this._createRepPromise()
}

NSClient.prototype.sendWho = function(logins) {
  if (typeof logins == "string") {
    logins = [logins]
  }
  this.pushLine("user_cmd who " + makeLoginList(logins))
  var D = Q.defer()
  this._whoQueue.push({defer: D, logins: logins})
  return D.promise
}

NSClient.prototype.doAuthentication = function(login, passwd) {
  if (this._salutData == undefined) return Q.reject("salut never happened")
  var self = this
    , data = this._salutData
    , salutHash = crypto.createHash("md5")
  salutHash.update(`${data.hash}-${data.ip}/${data.port}${passwd}`)
  salutHash = salutHash.digest("hex")
  return this.sendAuthAg()
    .then(function(res) {
      if (res.code != 2) return Q.reject("Can't ask authentication.")
      return self.sendExtUserLog(login, salutHash)
    })
    .then(function(res) {
      if (res.code != 2) return Q.reject("Authentication failed.")
    })
}

// Netsoul default handling

NSClient.prototype._onRep = function(words) {
  var data = {code: parseInt(words[1]), text: words.slice(2).join(" ")}
    , d = this._repQueue.shift()
  this.emit("rep", data.code, data.text)
  if (d !== undefined) return d.resolve(data);
  this.emit("unexpectedRep", data.code, data.text);
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
  var tmp = words[1].split(":")
    , trust_levels = tmp[2].split("/")
    , user_data = tmp[3].split("@")
    , cmd = words.slice(3)
    , data = {
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
    case "login": this._onCmdLogin(data); break
    case "logout": this._onCmdLogout(data); break
    case "who": this._onCmdWho(data, cmd); break
    case "state": this._onCmdState(data, cmd); break
    default:
      if (cmd.length == 3 && cmd[2].startsWith("dst=")) {
        this._onCmdOther(data, cmd)
      } else {
        this.emit("unknownUserCmd", data, cmd)
      }
      break
  }
}

// Netsoul original user_cmd handling

NSClient.prototype._onCmdWho = function(sender, data) {
  if (data[1] == "res") {
    var who = this._whoQueue.shift()
      , whoBuffer = this._whoBuffer
    this._whoBuffer = []
    if (who !== undefined) {
      var whoResult = {
        logins: who.logins,
        result: whoBuffer
      }
      this.emit("userCmdWhoEnd", sender, whoResult)
      return who.defer.resolve(whoResult)
    }
    this.emit("unexpectedUserCmdWhoEnd", whoBuffer)
  } else {
    var state = data[11].split(":")
      , whoData = {
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
    , state = {
      state: tmp[0],
      timestamp: prseInt(tmp[1])
    }
  this.emit("userCmdState", sender, state)
}

NSClient.prototype._onCmdLogin = function(sender) {
  this.emit("userCmdLogin", sender)
}

NSClient.prototype._onCmdLogout = function(sender) {
  this.emit("userCmdLogout", sender)
}

NSClient.prototype._onCmdOther = function(sender, data) {
  var otherData = {
    cmd: data[0],
    data: decodeURIComponent(data[1]),
    dests: parseLoginList(data[2].slice(4))
  }
  this.emit("userCmdOther", sender, otherData)
  var fn = this._userCmdCustom[otherData.cmd]
  if (fn !== undefined) {
    return fn.call(this, sender, otherData.data, otherData.dests)
  }
  this.emit("userCmdCustom", sender, otherData)
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
    var d = {
      name: decodeURIComponent(tmp[0]),
      size: parseInt(tmp[1]),
      desc: decodeURIComponent(tmp[2]),
      method: tmp[3]
    }
    this.emit("userCmdFileAsk", sender, d, dests)
  }
}

NSClient.prototype._onCmdFileStart = function(sender, data, dests) {
  var tmp = data.split(" ")
  if (tmp.length == 3) {
    var d = {
      name: decodeURIComponent(tmp[0]),
      ip: parseInt(tmp[1]),
      port: decodeURIComponent(tmp[2])
    }
    this.emit("userCmdFileAsk", sender, d, dests)
  }
}

// Data handling

NSClient.prototype._createRepPromise = function() {
  var d = Q.defer()
  this._repQueue.push(d)
  return d.promise
}

module.exports = NSClient
