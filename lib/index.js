(function() {
  var DEFAULT_OPTS, NSClient, Q, ThroughConstructor, _, crypto, makeLoginList, os, parseLoginList, through,
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  os = require("os");

  crypto = require("crypto");

  _ = require("lodash");

  Q = require("q");

  through = require("through2");

  DEFAULT_OPTS = {
    location: os.hostname() || "netsoul-protocol",
    resource: "netsoul-protocol",
    autoPing: true,
    lineDelim: /\r?\n/
  };

  makeLoginList = function(logins) {
    var tmp;
    switch (typeof logins) {
      case "string":
        return logins;
      case "number":
        return ":" + logins;
      default:
        tmp = _.map(logins, function(login) {
          switch (typeof login) {
            case "number":
              return ":" + login;
            case "string":
              return login;
            default:
              return "";
          }
        });
        return "{" + tmp + "}";
    }
  };

  parseLoginList = function(str) {
    var logins;
    logins = str.startsWith("{") && str.endsWith("}") ? str.slice(1, -1).split(",") : [str];
    return _.map(logins, function(login) {
      if (login.startsWith(":")) {
        return parseInt(login.slice(1));
      } else {
        return login;
      }
    });
  };

  ThroughConstructor = through.ctor(function(chunk, enc, cb) {
    var matches;
    matches = (this._buffer + chunk.toString()).split(this._opts.lineDelim);
    this._buffer = matches.pop();
    _.forEach(matches, (function(_this) {
      return function(line) {
        var words;
        _this.emit("line", line);
        words = line.split(" ");
        if (words.length > 0) {
          switch (words[0]) {
            case "rep":
              return _this._onRep(words);
            case "ping":
              return _this._onPing(words);
            case "salut":
              return _this._onSalut(words);
            case "user_cmd":
              return _this._onUserCmd(words);
            default:
              return _this.emit("unknownLine", words);
          }
        }
      };
    })(this));
    return cb();
  });

  NSClient = (function(superClass) {
    extend(NSClient, superClass);

    function NSClient(opts) {
      NSClient.__super__.constructor.call(this);
      opts = _.pick(opts, _.keys(DEFAULT_OPTS));
      this._opts = opts = _.extend(DEFAULT_OPTS, opts);
      this._buffer = String();
      this._repQueue = [];
      this._whoQueue = [];
      this._whoBuffer = [];
      this._salutData = null;
      this._userCmdCustom = {
        msg: this._onCmdMsg,
        dotnetSoul_UserTyping: this._onCmdTyping,
        dotnetSoul_UserCancelledTyping: this._onCmdCancelledTyping,
        file_ask: this._onCmdFileAsk,
        file_start: this._onCmdFileStart
      };
      this.info = {};
      if (this._opts.autoPing) {
        this.on("ping", this.sendPing);
      }
    }

    NSClient.prototype._createRepPromise = function() {
      var D;
      D = Q.defer();
      this._repQueue.push(D);
      return D.promise;
    };

    NSClient.prototype.pushLine = function(line) {
      this.emit("pushLine", line);
      return this.push(line + "\n");
    };

    NSClient.prototype.sendExit = function() {
      return this.pushLine("exit");
    };

    NSClient.prototype.sendPing = function(time) {
      return this.pushLine("ping " + time);
    };

    NSClient.prototype.sendState = function(state, time) {
      if (time == null) {
        time = Date.now() / 1000;
      }
      return this.pushLine("state " + state + ":" + (parseInt(time)));
    };

    NSClient.prototype.sendWatch = function(logins) {
      return this.pushLine("user_cmd watch_log_user " + (makeLoginList(logins)));
    };

    NSClient.prototype.sendCmdUser = function(cmd, data, dests) {
      if ((cmd != null) && (data != null) && (dests != null)) {
        return this.pushLine("user_cmd msg_user " + (makeLoginList(dests)) + " " + cmd + " " + (encodeURIComponent(data)));
      }
    };

    NSClient.prototype.sendMsg = function(msg, dests) {
      return this.sendCmdUser("msg", msg, dests);
    };

    NSClient.prototype.sendTyping = function(dests) {
      return this.sendCmdUser("dotnetSoul_UserTyping", "null", dests);
    };

    NSClient.prototype.sendCancelledTyping = function(dests) {
      return this.sendCmdUser("dotnetSoul_UserCancelledTyping", "null", dests);
    };

    NSClient.prototype.sendFileAsk = function(name, size, desc, dests) {
      return this.sendCmdUser("file_ask", (encodeURIComponent(name)) + " " + size + " " + (encodeURIComponent(desc)) + " passive", dests);
    };

    NSClient.prototype.sendFileStart = function(name, ip, port, dests) {
      return this.sendCmdUser("file_start", (encodeURIComponent(name)) + " " + ip + " " + port, dests);
    };

    NSClient.prototype.sendAuthAg = function() {
      this.pushLine("auth_ag ext_user none none");
      return this._createRepPromise();
    };

    NSClient.prototype.sendExtUserLog = function(login, hash) {
      this.pushLine("ext_user_log " + login + " " + hash + " " + (encodeURIComponent(this._opts.location)) + " " + (encodeURIComponent(this._opts.resource)));
      return this._createRepPromise();
    };

    NSClient.prototype.sendWho = function(logins) {
      var D;
      logins = typeof logins === "string" ? [logins] : logins;
      this.pushLine("user_cmd who " + (makeLoginList(logins)));
      D = Q.defer();
      this._whoQueue.push({
        defer: D,
        logins: logins
      });
      return D.promise;
    };

    NSClient.prototype.doAuthentication = function(login, passwd) {
      var data, salutHash;
      if (this._salutData == null) {
        return Q.reject("salut never happened");
      }
      data = this._salutData;
      salutHash = crypto.createHash("md5");
      salutHash.update(data.hash + "-" + data.ip + "/" + data.port + passwd);
      salutHash = salutHash.digest("hex");
      return this.sendAuthAg().then((function(_this) {
        return function(res) {
          if (res.code === 2) {
            return _this.sendExtUserLog(login, salutHash);
          } else {
            return Q.reject("Can't ask authentication.");
          }
        };
      })(this)).then((function(_this) {
        return function(res) {
          if (res.code !== 2) {
            return Q.reject("Authentication failed.");
          }
        };
      })(this));
    };

    NSClient.prototype._onRep = function(words) {
      var d, data;
      data = {
        code: parseInt(words[1]),
        text: words.slice(2).join(" ")
      };
      d = this._repQueue.shift();
      this.emit("rep", data.code, data.text);
      if (d != null) {
        return d.resolve(data);
      } else {
        return this.emit("unexpectedRep", data.code, data.text);
      }
    };

    NSClient.prototype._onPing = function(words) {
      return this.emit("ping", parseInt(words[1]));
    };

    NSClient.prototype._onSalut = function(words) {
      this._salutData = {
        socket: parseInt(words[1]),
        hash: words[2],
        ip: words[3],
        port: parseInt(words[4]),
        timestamp: parseInt(words[5])
      };
      this.info = _.pick(this._salutData, "socket", "ip", "port");
      return this.emit("salut", this._salutData);
    };

    NSClient.prototype._onUserCmd = function(words) {
      var cmd, data, tmp, trust_levels, user_data;
      tmp = words[1].split(":");
      trust_levels = tmp[2].split("/");
      user_data = tmp[3].split("@");
      cmd = words.slice(3);
      data = {
        socket: parseInt(tmp[0]),
        trust_level_low: parseInt(trust_levels[0]),
        trust_level_high: parseInt(trust_levels[1]),
        login: user_data[0],
        ip: user_data[1],
        workstation_type: tmp[4],
        location: decodeURIComponent(tmp[5]),
        group: tmp[6]
      };
      this.emit("userCmd", data, cmd);
      switch (cmd[0]) {
        case "login":
          return this._onCmdLogin(data);
        case "logout":
          return this._onCmdLogout(data);
        case "who":
          return this._onWho(data, cmd);
        case "state":
          return this._onCmdState(data, cmd);
        default:
          if (cmd.length === 3 && cmd[2].startsWith("dst=")) {
            return this._onCmdOther(data, cmd);
          } else {
            return this.emit("unknownUserCmd", data, cmd);
          }
      }
    };

    NSClient.prototype._onCmdWho = function(sender, data) {
      var state, who, whoBuffer, whoData, whoResult;
      if (data[1] === "rep") {
        who = this._whoQueue.shift();
        whoBuffer = this._whoBuffer;
        this._whoBuffer = [];
        if (who == null) {
          return this.emit("unexpectedUserCmdWhoEnd", whoBuffer);
        }
        whoResult = {
          logins: who.logins,
          result: whoBuffer
        };
        this.emit("userCmdWhoEnd", send, whoResult);
        return who.defer.resolve(whoResult);
      } else {
        state = data[11].split(":");
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
        };
        this.emit("userCmdWho", send, whoData);
        return this._whoBuffer.push(whoData);
      }
    };

    NSClient.prototype._onCmdState = function(sender, data) {
      var state, tmp;
      tmp = data[1].split(":");
      state = {
        state: tmp[0],
        timestamp: parseInt(tmp[1])
      };
      return this.emit("userCmdState", sender, state);
    };

    NSClient.prototype._onCmdLogin = function(sender) {
      return this.emit("userCmdLogin", sender);
    };

    NSClient.prototype._onCmdLogout = function(sender) {
      return this.emit("userCmdLogout", sender);
    };

    NSClient.prototype._onCmdOther = function(sender, data) {
      var fn, oData;
      oData = {
        cmd: data[0],
        data: decodeURIComponent(data[1]),
        dests: parseLoginList(data[2].slice(4))
      };
      this.emit("userCmdOther", sender, oData);
      fn = this._userCmdCustom[oData.cmd];
      if (fn != null) {
        return fn.call(this, sender, oData.data, oData.dests);
      } else {
        return this.emit("userCmdCustom", sender, oData);
      }
    };

    NSClient.prototype._onCmdMsg = function(sender, data, dests) {
      return this.emit("userCmdMsg", sender, data, dests);
    };

    NSClient.prototype._onCmdTyping = function(sender, data, dests) {
      return this.emit("userCmdTyping", sender, dests);
    };

    NSClient.prototype._onCmdCancelledTyping = function(sender, data, dests) {
      return this.emit("userCmdCancelledTyping", sender, dests);
    };

    NSClient.prototype._onCmdFileAsk = function(sender, data, dests) {
      var d, tmp;
      tmp = data.split(" ");
      if (tmp.length === 4) {
        d = {
          name: decodeURIComponent(tmp[0]),
          size: parseInt(tmp[1]),
          desc: decodeURIComponent(tmp[2]),
          method: tmp[3]
        };
        return this.emit("userCmdFileAsk", sender, d, dests);
      }
    };

    NSClient.prototype._onCmdFileStart = function(sender, data, dests) {
      var d, tmp;
      tmp = data.split(" ");
      if (tmp.length === 3) {
        d = {
          name: decodeURIComponent(tmp[0]),
          ip: parseInt(tmp[1]),
          port: decodeURIComponent(tmp[2])
        };
        return this.emit("userCmdFileAsk", sender, d, dests);
      }
    };

    return NSClient;

  })(ThroughConstructor);

  module.exports = NSClient;

}).call(this);
