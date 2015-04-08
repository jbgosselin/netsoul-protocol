#!/usr/bin/env node
var net = require("net"),
    readline = require("readline"),
    NSClient = require("./src")

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
  var sock = net.createConnection(
    NSClient.NS_PORT,
    NSClient.NS_HOST
  )

  sock.on("connect", function() {
    var client = new NSClient()
    sock.pipe(client).pipe(sock)

    client.on("line", function(line) {
      console.log("<" + line)
    })

    client.on("pushLine", function(line) {
      console.log(">" + line)
    })

    client.on("salut", function(data) {
      client.doAuthentication(login, passwd).then(function() {
        console.log("[Info] Authentication OK.")
        client.sendState("actif")
      }).catch(function(err) {
        console.error("[Error]" + err)
        client.sendExit()
      })
    })

    client.once("exit", function() {
      console.log("[Info] Connection closed.")
    })

    client.on("userCmdMsg", function(sender, msg, dests) {
      console.log(["[", sender.login, "@", sender.location, "] ", msg].join())
    })
  })

  sock.once("error", function(err) {
    console.error("CATCH ERROR")
    console.error(err)
  })
}

main()
