#!/usr/bin/env node
var net = require("net")
  , util = require("util")
  , readline = require('readline')
  , NSClient = require("./lib/index.js")
  , NS_HOST = "ns-server.epita.fr"
  , NS_PORT = 4242

function main() {
  var rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  })

  rl.question("login: ", function(login) {
    rl.question("password: ", function(passwd) {
      connect(login, passwd)
      rl.close()
    })
  })
}

function connect(login, passwd) {
  var sock = net.createConnection(NS_PORT, NS_HOST)

  sock.on("connect", function() {
    var client = new NSClient()

    sock.pipe(client).pipe(sock) // There is the pipe magic !

    client.on("line", function(line) {
      console.log("<%s", line)
    })

    client.on("pushLine", function(line) {
      console.log(">%s", line)
    })

    client.on("salut", function(data) {
      client.doAuthentication(login, passwd)
        .then(function() {
          console.log("[Info] Authentication OK.")
          client.sendState("actif")
        }, function(err) {
          console.error("[Error] %s", err)
          client.sendExit()
        })
    })

    client.once("exit", function() {
      console.log("[Info] Connection closed.")
    });

    client.on("userCmdMsg", function(sender, msg, dests) {
      console.log("[%s@%s] %s", sender.login, sender.location, msg)
    })
  })

  sock.once("error", function(err) {
    console.error("CATCH ERROR")
    console.error(err)
  });
}

main()
