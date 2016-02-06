"use strict";

import os from "os";
import crypto from "crypto";
import _ from "lodash";
import { Duplex } from "readable-stream";
import Promise from "bluebird";

const DEFAULT_OPTS = {
  location: os.hostname() || "netsoul-protocol",
  resource: "netsoul-protocol",
  autoPing: true,
  lineDelim: /\r?\n/,
};

class Defer {
  constructor() {
    this.resolve = null;
    this.reject = null;
    this.promise = new Promise((resolve, reject) => {
      this.resolve = resolve;
      this.reject = reject;
    });
  }
}

const makeLoginList = (logins) => {
  switch (typeof logins) {
    case "string": return logins;
    case "number": return `:${logins}`;
    default: return (_.isArray(logins)) ? `{${ _.map(logins, makeLoginList).join(",") }}` : "";
  }
};

const parseLoginList = (str) => _.map(
  (() => {
    if (str.startsWith("{") && str.endsWith("}")) {
      return str.slice(1, -1).split(",");
    }
    return [str];
  })(),
  (login) => (login.startsWith(":")) ? parseInt(login.slice(1), 10) : login
);

const NSClient = module.exports = class extends Duplex {
  constructor(opts) {
    super();
    this._buffer = "";
    this._outBuffer = "";
    this._repQueue = [];
    this._whoQueue = [];
    this._whoBuffer = [];
    this._salutData = null;
    this.info = {};

    this._opts = _.extend(DEFAULT_OPTS, opts);
    this._userCmdCustom = {
      msg: this._onCmdMsg,
      dotnetSoul_UserTyping: this._onCmdTyping,
      dotnetSoul_UserCancelledTyping: this._onCmdCancelledTyping,
      file_ask: this._onCmdFileAsk,
      file_start: this._onCmdFileStart,
    };
    if (this._opts.autoPing) this.on("ping", this.sendPing);
  }

  _createRepPromise() {
    const D = new Defer();
    this._repQueue.push(D);
    return D.promise;
  }

  _read() {}

  _write(chunk, enc, next) {
    const matches = (this._buffer + chunk.toString()).split(this._opts.lineDelim);
    this._buffer = matches.pop();
    _.forEach(matches, (line) => {
      this.emit("line", line);
      const words = line.split(" ");
      if (words.length > 0) {
        switch (words[0]) {
          case "rep": return this._onRep(words);
          case "ping": return this._onPing(words);
          case "salut": return this._onSalut(words);
          case "user_cmd": return this._onUserCmd(words);
          default: return this.emit("unknownLine", words);
        }
      }
    });
    next();
  }

  // Methods

  pushLine(line) {
    this.emit("pushLine", line);
    this.push(`${line}\n`);
  }

  sendExit() {
    this.pushLine("exit");
  }

  sendPing(time) {
    this.pushLine(`ping ${time}`);
  }

  sendState(state, time = (Date.now() / 1000)) {
    this.pushLine(`state ${state}:${parseInt(time, 10)}`);
  }

  sendWatch(logins) {
    this.pushLine(`user_cmd watch_log_user ${makeLoginList(logins)}`);
  }

  sendCmdUser(cmd, dt, ds) {
    this.pushLine(`user_cmd msg_user ${makeLoginList(ds)} ${cmd} ${encodeURIComponent(dt)}`);
  }

  sendMsg(msg, dests) {
    this.sendCmdUser("msg", msg, dests);
  }

  sendTyping(dests) {
    this.sendCmdUser("dotnetSoul_UserTyping", "null", dests);
  }

  sendCancelledTyping(dests) {
    this.sendCmdUser("dotnetSoul_UserCancelledTyping", "null", dests);
  }

  sendFileAsk(name, size, desc, dests) {
    const enc = encodeURIComponent;
    this.sendCmdUser("file_ask", `${enc(name)} ${size} ${enc(desc)} passive`, dests);
  }

  sendFileStart(name, ip, port, dests) {
    this.sendCmdUser("file_start", `${encodeURIComponent(name)} ${ip} ${port}`, dests);
  }

  sendAuthAg() {
    this.pushLine("auth_ag ext_user none none");
    return this._createRepPromise();
  }

  sendExtUserLog(login, hash) {
    const enc = encodeURIComponent;
    const o = this._opts;
    this.pushLine(`ext_user_log ${login} ${hash} ${enc(o.location)} ${enc(o.resource)}`);
    return this._createRepPromise();
  }

  sendWho(logins) {
    const goodLogins = (typeof(logins) === "string") ? [logins] : logins;
    this.pushLine(`user_cmd who ${makeLoginList(goodLogins)}`);
    const D = new Defer();
    this._whoQueue.push({ defer: D, logins: goodLogins });
    return D.promise;
  }

  doAuthentication(login, passwd) {
    if (this._salutData === undefined) return Promise.reject("salut never happened");
    const data = this._salutData;
    const salutHash = crypto.createHash("md5");
    salutHash.update(`${data.hash}-${data.ip}/${data.port}${passwd}`);
    const digestHash = salutHash.digest("hex");
    return this.sendAuthAg()
      .then((res) => (res.code === 2) ? (
        this.sendExtUserLog(login, digestHash)
      ) : (
        Promise.reject("Can't ask authentication.")
      ))
      .then((res) => (res.code !== 2) ? Promise.reject("Authentication failed.") : null);
  }

  // Netsoul default handling

  _onRep(words) {
    const data = {
      code: parseInt(words[1], 10),
      text: words.slice(2).join(" "),
    };
    const D = this._repQueue.shift();
    this.emit("rep", data.code, data.text);
    if (D !== undefined) return D.resolve(data);
    this.emit("unexpectedRep", data.code, data.text);
  }

  _onPing(words) {
    this.emit("ping", parseInt(words[1], 10));
  }

  _onSalut(words) {
    this._salutData = {
      socket: parseInt(words[1], 10),
      hash: words[2],
      ip: words[3],
      port: parseInt(words[4], 10),
      timestamp: parseInt(words[5], 10),
    };
    this.info = _.pick(this._salutData, "socket", "ip", "port");
    this.emit("salut", this._salutData);
  }

  _onUserCmd(words) {
    const tmp = words[1].split(":");
    const trustLevels = tmp[2].split("/");
    const userData = tmp[3].split("@");
    const cmd = words.slice(3);
    const data = {
      socket: parseInt(tmp[0], 10),
      trustLevelLow: parseInt(trustLevels[0], 10),
      trustLevelHigh: parseInt(trustLevels[1], 10),
      login: userData[0],
      ip: userData[1],
      workstationType: tmp[4],
      location: decodeURIComponent(tmp[5]),
      group: tmp[6],
    };
    this.emit("userCmd", data, cmd);
    switch (cmd[0]) {
      case "login": return this._onCmdLogin(data);
      case "logout": return this._onCmdLogout(data);
      case "who": return this._onWho(data, cmd);
      case "state": return this._onCmdState(data, cmd);
      default:
        if (cmd.length === 3 && cmd[2].startsWith("dst=")) return this._onCmdOther(data, cmd);
        this.emit("unknownUserCmd", data, cmd);
    }
  }

  // Netsoul original user_cmd handling

  _onCmdWho(sender, data) {
    if (data[1] === "rep") {
      const who = this._whoQueue.shift();
      const whoBuffer = this._whoBuffer;
      this._whoBuffer = [];
      if (who === undefined) return this.emit("unexpectedUserCmdWhoEnd", whoBuffer);
      const whoResult = { logins: who.logins, result: whoBuffer };
      this.emit("userCmdWhoEnd", sender, whoResult);
      who.defer.resolve(whoResult);
      return undefined;
    }
    const state = data[11].split(":");
    const whoData = {
      socket: parseInt(data[1], 10),
      login: data[2],
      ip: data[3],
      loginTimestamp: parseInt(data[4], 10),
      lastChangeTimestamp: parseInt(data[5], 10),
      trustLevelLow: parseInt(data[6], 10),
      trustLevelHigh: parseInt(data[7], 10),
      workstationType: data[8],
      location: decodeURIComponent(data[9]),
      group: data[10],
      state: {
        state: state[0],
        timestamp: parseInt(state[1], 10),
      },
      resource: decodeURIComponent(data[12]),
    };
    this.emit("userCmdWho", sender, whoData);
    this._whoBuffer.push(whoData);
  }

  _onCmdState(sender, data) {
    const tmp = data[1].split(":");
    this.emit("userCmdState", sender, {
      state: tmp[0],
      timestamp: parseInt(tmp[1], 10),
    });
  }

  _onCmdLogin(sender) {
    this.emit("userCmdLogin", sender);
  }

  _onCmdLogout(sender) {
    this.emit("userCmdLogout", sender);
  }

  _onCmdOther(sender, data) {
    const oData = {
      cmd: data[0],
      data: decodeURIComponent(data[1]),
      dests: parseLoginList(data[2].slice(4)),
    };
    const fn = this._userCmdCustom[oData.cmd];
    this.emit("userCmdOther", sender, oData);
    if (fn !== undefined) return fn(sender, oData.data, oData.dests);
    this.emit("userCmdCustom", sender, oData);
  }

  // Netsoul other user_cmd handling

  _onCmdMsg(sender, data, dests) {
    this.emit("userCmdMsg", sender, data, dests);
  }

  _onCmdTyping(sender, data, dests) {
    this.emit("userCmdTyping", sender, dests);
  }

  _onCmdCancelledTyping(sender, data, dests) {
    this.emit("userCmdCancelledTyping", sender, dests);
  }

  _onCmdFileAsk(sender, data, dests) {
    const tmp = data.split(" ");
    if (tmp.length === 4) {
      this.emit("userCmdFileAsk", sender, {
        name: decodeURIComponent(tmp[0]),
        size: parseInt(tmp[1], 10),
        desc: decodeURIComponent(tmp[2]),
        method: tmp[3],
      }, dests);
    }
  }

  _onCmdFileStart(sender, data, dests) {
    const tmp = data.split(" ");
    if (tmp.length === 3) {
      this.emit("userCmdFileAsk", sender, {
        name: decodeURIComponent(tmp[0]),
        ip: parseInt(tmp[1], 10),
        port: decodeURIComponent(tmp[2]),
      }, dests);
    }
  }
};

NSClient.NS_HOST = "ns-server.epita.fr";
NSClient.NS_PORT = 4242;
