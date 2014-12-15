var stream = require("stream");
var util = require("util");
var os = require("os");
var crypto = require("crypto");
var _ = require("underscore");
var Q = require("q");
var NSParser = require("./netsoul_parser.js");

var DEFAULT_LINEDELIM = /\r?\n/;
var DEFAULT_LOCATION = os.hostname() || "netsoul-protocol";
var DEFAULT_RESOURCE = "netsoul-protocol";

var DEFAULT_OPTS = {
  location: DEFAULT_LOCATION,
  resource: DEFAULT_RESOURCE,
  autoPing: true,
  lineDelim: DEFAULT_LINEDELIM
};

function NSClient(opts) {
  // call Duplex constructor
  stream.Duplex.call(this);

  opts = _.pick(opts, _.keys(DEFAULT_OPTS));
  this._opts = opts = _.extend(DEFAULT_OPTS, opts);;
  this._buffer = String(); // Data buffer
  this._repQueue = []; // Waitings response
  this._whoQueue = []; // Waitings who response
  this._whoBuffer = []; // Who tmp buffer
  this._salutData = undefined;
  this.info = {};

  this.once("finish", this._onFinish);

  if (this._opts.autoPing) {
    this.on("ping", this.sendPing);
  }
}

util.inherits(NSClient, stream.Duplex);

// Static methods

NSClient.makeLoginList = function(logins) {
  if (typeof logins == "string") return logins;
  if (typeof logins == "number") return ":" + logins;
  return "{" + _.map(logins, function(login) {
    switch (typeof login) {
      case "number":
        return ":" + login;
      case "string":
        return login;
      default:
        return "";
    }
  }) + "}";
};

// Methods

NSClient.prototype.pushLine = function() {
  var line = util.format.apply({}, arguments);
  this.emit("pushLine", line);
  this.push(line + "\n");
};

NSClient.prototype.sendExit = function() {
  this.pushLine("exit");
};

NSClient.prototype.sendPing = function(time) {
  this.pushLine("ping %d", time);
};

NSClient.prototype.sendState = function(state, time) {
  time = time || parseInt(Date.now() / 1000);
  this.pushLine("state %s:%d", state, parseInt(time));
};

NSClient.prototype.sendWatch = function(logins) {
  this.pushLine("user_cmd watch_log_user %s", NSClient.makeLoginList(logins));
};

NSClient.prototype.sendCmdUser = function(cmd, data, dests) {
  if (cmd != undefined && data != undefined && dests != undefined) {
    this.pushLine("user_cmd msg_user %s %s %s", NSClient.makeLoginList(dests), cmd, encodeURIComponent(data));
  }
};

NSClient.prototype.sendMsg = function(msg, dests) {
  this.sendCmdUser("msg", msg, dests);
};

NSClient.prototype.sendTyping = function(dests) {
  this.sendCmdUser("dotnetSoul_UserTyping", "null", dests);
};

NSClient.prototype.sendCancelledTyping = function(dests) {
  this.sendCmdUser("dotnetSoul_UserCancelledTyping", "null", dests);
};

NSClient.prototype.sendFileAsk = function(name, size, desc, dests) {
  var data = util.format("%s %d %s passive", encodeURIComponent(name), size, encodeURIComponent(desc));
  this.sendCmdUser("file_ask", data, dests);
};

NSClient.prototype.sendFileStart = function(name, ip, port, dests) {
  var data = util.format("%s %s %d", encodeURIComponent(name), ip, port);
  this.sendCmdUser("file_start", data, dests);
};

NSClient.prototype.sendAuthAg = function() {
  this.pushLine("auth_ag ext_user none none");
  return this._createRepPromise();
};

NSClient.prototype.sendExtUserLog = function(login, hash) {
  this.pushLine("ext_user_log %s %s %s %s", login, hash, encodeURIComponent(this._opts.location), encodeURIComponent(this._opts.resource));
  return this._createRepPromise();
};

NSClient.prototype.sendWho = function(logins) {
  if (typeof logins == "string") {
    logins = [logins];
  }
  this.pushLine("user_cmd who %s", NSClient.makeLoginList(logins));
  var d = Q.defer();
  this._whoQueue.push({defer: d, logins: logins});
  return d.promise;
};

NSClient.prototype.doAuthentication = function(login, passwd) {
  if (this._salutData !== undefined) {
    var data = this._salutData;
    var salutHash = crypto.createHash("md5");
    salutHash.update(util.format("%s-%s/%s%s", data.hash, data.ip, data.port, passwd));
    salutHash = salutHash.digest("hex");
    return this.sendAuthAg()
      .then(function(res) {
        if (res.code != 2) return Q.reject("Can't ask authentication.");
        return this.sendExtUserLog(login, salutHash)
      }.bind(this))
      .then(function(res) {
        if (res.code != 2) return Q.reject("Authentication failed.");
      }.bind(this));
  }
  return Q.reject("salut never happened");
};

// Netsoul default handling

NSClient.prototype._onRep = function(data) {
  this.emit("rep", data.nb, data.text);
  var d = this._repQueue.shift();
  if (d !== undefined) return d.resolve(data);
  this.emit("unexpectedRep", data.nb, data.text);
};

NSClient.prototype._onPing = function(data) {
  this.emit("ping", data.timestamp);
};

NSClient.prototype._onSalut = function(data) {
  this._salutData = data;
  this.info = _.pick(data, "socket", "ip", "port");
  this.emit("salut", data);
};

NSClient.prototype._onUserCmd = function(data) {
  this.emit("userCmd", data);
  var fn = USER_CMD_TYPES[data.cmd.type];
  if (fn !== undefined) {
    return fn.call(this, data, data.cmd.data);
  }
  this.emit("unknownUserCmd", data);
};

// Netsoul original user_cmd handling

NSClient.prototype._onCmdWho = function(sender, data) {
  this.emit("userCmdWho", sender, data);
  this._whoBuffer.push(data);
};

NSClient.prototype._onCmdWhoEnd = function(sender) {
  var who = this._whoQueue.shift();
  var whoBuffer = this._whoBuffer;
  this._whoBuffer = [];
  if (who !== undefined) {
    var whoResult = {
      logins: who.logins,
      result: whoBuffer
    };
    this.emit("userCmdWhoEnd", sender, whoResult);
    return who.defer.resolve(whoResult);
  }
  this.emit("unexpectedUserCmdWhoEnd", whoBuffer);
};

NSClient.prototype._onCmdState = function(sender, data) {
  this.emit("userCmdState", sender, data);
};

NSClient.prototype._onCmdLogin = function(sender) {
  this.emit("userCmdLogin", sender);
};

NSClient.prototype._onCmdLogout = function(sender) {
  this.emit("userCmdLogout", sender);
};

NSClient.prototype._onCmdOther = function(sender, data) {
  this.emit("userCmdOther", sender, data);
  var fn = USER_CMD_OTHER[data.cmd];
  if (fn !== undefined) {
    return fn.call(this, sender, data.data, data.dests);
  }
  this.emit("userCmdCustom", sender, data);
};

var USER_CMD_TYPES = {
  login: NSClient.prototype._onCmdLogin,
  logout: NSClient.prototype._onCmdLogout,
  who: NSClient.prototype._onCmdWho,
  who_end: NSClient.prototype._onCmdWhoEnd,
  state: NSClient.prototype._onCmdState,
  other: NSClient.prototype._onCmdOther
};

// Netsoul other user_cmd handling

NSClient.prototype._onCmdMsg = function(sender, data, dests) {
  this.emit("userCmdMsg", sender, data, dests);
};

NSClient.prototype._onCmdTyping = function(sender, data, dests) {
  this.emit("userCmdTyping", sender, dests);
};

NSClient.prototype._onCmdCancelledTyping = function(sender, data, dests) {
  this.emit("userCmdCancelledTyping", sender, dests);
};

NSClient.prototype._onCmdFileAsk = function(sender, data, dests) {
  var tmp = data.split(" ");
  if (data.length == 4) {
    var d = {
      name: decodeURIComponent(tmp[0]),
      size: parseInt(tmp[1]),
      desc: decodeURIComponent(tmp[2]),
      method: tmp[3]
    };
    this.emit("userCmdFileAsk", sender, d, dests);
  }
};

NSClient.prototype._onCmdFileStart = function(sender, data, dests) {
  var tmp = data.split(" ");
  if (data.length == 3) {
    var d = {
      name: decodeURIComponent(tmp[0]),
      ip: parseInt(tmp[1]),
      port: decodeURIComponent(tmp[2])
    };
    this.emit("userCmdFileAsk", sender, d, dests);
  }
};

var USER_CMD_OTHER = {
  msg: NSClient.prototype._onCmdMsg,
  dotnetSoul_UserTyping: NSClient.prototype._onCmdTyping,
  dotnetSoul_UserCancelledTyping: NSClient.prototype._onCmdCancelledTyping,
  file_ask: NSClient.prototype._onCmdFileAsk,
  file_start: NSClient.prototype._onCmdFileStart
};

// Data handling

NSClient.prototype._write = function(data, encoding, cb) {
  var matches = (this._buffer + data.toString()).split(this._opts.lineDelim);
  this._buffer = matches.pop();
  matches.forEach(this._onLine.bind(this));
  cb(null);
};

NSClient.prototype._read = _.noop;

NSClient.prototype._onFinish = function() {
  this.push(null);
  while (this.read()) {}
  this.emit("exit");
};

var LINE_TYPE = {
  rep: NSClient.prototype._onRep,
  ping: NSClient.prototype._onPing,
  salut: NSClient.prototype._onSalut,
  user_cmd: NSClient.prototype._onUserCmd
};

NSClient.prototype._onLine = function(line) {
  this.emit("line", line);
  var match;
  try {
    match = NSParser.parse(line);
  } catch(err) {
    this.emit("unknownLine", line, err);
    return;
  }
  var fn = LINE_TYPE[match.type];
  if (fn !== undefined) {
    fn.call(this, match.data);
  }
};

NSClient.prototype._createRepPromise = function() {
  var d = Q.defer();
  this._repQueue.push(d);
  return d.promise;
};

module.exports = NSClient;
