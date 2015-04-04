os = require "os"
crypto = require "crypto"
_ = require "lodash"
Q = require "q"
through = require "through2"

DEFAULT_OPTS =
  location: os.hostname() || "netsoul-protocol"
  resource: "netsoul-protocol"
  autoPing: true
  lineDelim: /\r?\n/

makeLoginList = (logins) ->
  switch typeof logins
    when "string" then logins
    when "number" then ":#{logins}"
    else
      tmp = _.map logins, (login) ->
        switch typeof login
          when "number" then ":#{login}"
          when "string" then login
          else ""
      "{#{tmp}}"

parseLoginList = (str) ->
  logins = if str.startsWith("{") and str.endsWith("}") then str.slice(1, -1).split(",") else [str]
  _.map logins, (login) ->
    if login.startsWith(":") then parseInt login.slice(1) else login

ThroughConstructor = through.ctor (chunk, enc, cb) ->
  matches = (this._buffer + chunk.toString()).split this._opts.lineDelim
  this._buffer = matches.pop()
  _.forEach matches, (line) =>
    this.emit "line", line
    words = line.split " "
    if words.length > 0
      switch words[0]
        when "rep" then this._onRep words
        when "ping" then this._onPing words
        when "salut" then this._onSalut words
        when "user_cmd" then this._onUserCmd words
        else this.emit "unknownLine", words
  return cb()

class NSClient extends ThroughConstructor
  constructor: (opts) ->
    super()

    opts = _.pick opts, _.keys(DEFAULT_OPTS)
    @_opts = opts = _.extend DEFAULT_OPTS, opts
    @_buffer = String()
    @_repQueue = []
    @_whoQueue = []
    @_whoBuffer = []
    @_salutData = null
    @_userCmdCustom =
      msg: this._onCmdMsg
      dotnetSoul_UserTyping: this._onCmdTyping
      dotnetSoul_UserCancelledTyping: this._onCmdCancelledTyping
      file_ask: this._onCmdFileAsk
      file_start: this._onCmdFileStart
    @info = {}

    if @_opts.autoPing then this.on "ping", this.sendPing

  _createRepPromise: () ->
    D = Q.defer()
    @_repQueue.push D
    D.promise

  # Methods

  pushLine: (line) ->
    this.emit "pushLine", line
    this.push line + "\n"

  sendExit: () -> this.pushLine "exit"

  sendPing: (time) -> this.pushLine "ping #{time}"

  sendState: (state, time = Date.now() / 1000) -> this.pushLine "state #{state}:#{parseInt time}"

  sendWatch: (logins) -> this.pushLine "user_cmd watch_log_user #{makeLoginList logins}"

  sendCmdUser: (cmd, data, dests) -> if cmd? and data? and dests? then this.pushLine "user_cmd msg_user #{makeLoginList dests} #{cmd} #{encodeURIComponent data}"

  sendMsg: (msg, dests) -> this.sendCmdUser "msg", msg, dests

  sendTyping: (dests) -> this.sendCmdUser "dotnetSoul_UserTyping", "null", dests

  sendCancelledTyping: (dests) -> this.sendCmdUser "dotnetSoul_UserCancelledTyping", "null", dests

  sendFileAsk: (name, size, desc, dests) -> this.sendCmdUser "file_ask", "#{encodeURIComponent name} #{size} #{encodeURIComponent desc} passive", dests

  sendFileStart: (name, ip, port, dests) -> this.sendCmdUser "file_start", "#{encodeURIComponent name} #{ip} #{port}", dests

  sendAuthAg: () ->
    this.pushLine "auth_ag ext_user none none"
    this._createRepPromise()

  sendExtUserLog: (login, hash) ->
    this.pushLine "ext_user_log #{login} #{hash} #{encodeURIComponent @_opts.location} #{encodeURIComponent @_opts.resource}"
    this._createRepPromise()

  sendWho: (logins) ->
    logins = if typeof logins is "string" then [logins] else logins
    this.pushLine "user_cmd who #{makeLoginList logins}"
    D = Q.defer()
    @_whoQueue.push {defer: D, logins: logins}
    D.promise

  doAuthentication: (login, passwd) ->
    if not @_salutData? then return Q.reject "salut never happened"
    data = @_salutData
    salutHash = crypto.createHash "md5"
    salutHash.update "#{data.hash}-#{data.ip}/#{data.port}#{passwd}"
    salutHash = salutHash.digest "hex"
    this.sendAuthAg()
    .then (res) => if res.code == 2 then this.sendExtUserLog login, salutHash else Q.reject "Can't ask authentication."
    .then (res) => if res.code != 2 then Q.reject "Authentication failed."

  # Netsoul default handling

  _onRep: (words) ->
    data =
      code: parseInt words[1]
      text: words.slice(2).join " "
    d = @_repQueue.shift()
    this.emit "rep", data.code, data.text
    if d? then d.resolve data else this.emit "unexpectedRep", data.code, data.text

  _onPing: (words) -> this.emit "ping", parseInt words[1]

  _onSalut: (words) ->
    @_salutData =
      socket: parseInt words[1]
      hash: words[2]
      ip: words[3]
      port: parseInt words[4]
      timestamp: parseInt words[5]
    @info = _.pick @_salutData, "socket", "ip", "port"
    this.emit "salut", @_salutData

  _onUserCmd: (words) ->
    tmp = words[1].split ":"
    trust_levels = tmp[2].split "/"
    user_data = tmp[3].split "@"
    cmd = words.slice 3
    data =
      socket: parseInt tmp[0]
      trust_level_low: parseInt trust_levels[0]
      trust_level_high: parseInt trust_levels[1]
      login: user_data[0]
      ip: user_data[1]
      workstation_type: tmp[4]
      location: decodeURIComponent tmp[5]
      group: tmp[6]
    this.emit "userCmd", data, cmd
    switch cmd[0]
      when "login" then this._onCmdLogin data
      when "logout" then this._onCmdLogout data
      when "who" then this._onWho data, cmd
      when "state" then this._onCmdState data, cmd
      else
        if cmd.length == 3 and cmd[2].startsWith "dst=" then this._onCmdOther data, cmd else this.emit "unknownUserCmd", data, cmd

  # Netsoul original user_cmd handling

  _onCmdWho: (sender, data) ->
    if data[1] == "rep"
      who = @_whoQueue.shift()
      whoBuffer = @_whoBuffer
      @_whoBuffer = []
      if not who? then return this.emit "unexpectedUserCmdWhoEnd", whoBuffer
      whoResult =
        logins: who.logins
        result: whoBuffer
      this.emit "userCmdWhoEnd", send, whoResult
      who.defer.resolve whoResult
    else
      state = data[11].split ":"
      whoData =
        socket: parseInt data[1]
        login: data[2]
        ip: data[3]
        login_timestamp: parseInt data[4]
        last_change_timestamp: parseInt data[5]
        trust_level_low: parseInt data[6]
        trust_level_high: parseInt data[7]
        workstation_type: data[8]
        location: decodeURIComponent data[9]
        group: data[10]
        state:
          state: state[0]
          timestamp: parseInt state[1]
        resource: decodeURIComponent data[12]
      this.emit "userCmdWho", send, whoData
      @_whoBuffer.push whoData

  _onCmdState: (sender, data) ->
    tmp = data[1].split ":"
    state =
      state: tmp[0]
      timestamp: parseInt tmp[1]
    this.emit "userCmdState", sender, state

  _onCmdLogin: (sender) -> this.emit "userCmdLogin", sender

  _onCmdLogout: (sender) -> this.emit "userCmdLogout", sender

  _onCmdOther: (sender, data) ->
    oData =
      cmd: data[0]
      data: decodeURIComponent data[1]
      dests: parseLoginList data[2].slice 4
    this.emit "userCmdOther", sender, oData
    fn = @_userCmdCustom[oData.cmd]
    if fn? then fn.call this, sender, oData.data, oData.dests else this.emit "userCmdCustom", sender, oData

  # Netsoul other user_cmd handling

  _onCmdMsg: (sender, data, dests) -> this.emit "userCmdMsg", sender, data, dests

  _onCmdTyping: (sender, data, dests) -> this.emit "userCmdTyping", sender, dests

  _onCmdCancelledTyping: (sender, data, dests) -> this.emit "userCmdCancelledTyping", sender, dests

  _onCmdFileAsk: (sender, data, dests) ->
    tmp = data.split " "
    if tmp.length == 4
      d =
        name: decodeURIComponent tmp[0]
        size: parseInt tmp[1]
        desc: decodeURIComponent tmp[2]
        method: tmp[3]
      this.emit "userCmdFileAsk", sender, d, dests

  _onCmdFileStart: (sender, data, dests) ->
    tmp = data.split " "
    if tmp.length == 3
      d =
        name: decodeURIComponent tmp[0]
        ip: parseInt tmp[1]
        port: decodeURIComponent tmp[2]
      this.emit "userCmdFileAsk", sender, d, dests

module.exports = NSClient
