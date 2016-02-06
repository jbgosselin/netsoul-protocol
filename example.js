#!/usr/bin/env node
"use strict"
var net = require("net"),
    readline = require("readline"),
    NSClient = require("./lib")

function main() {
  var rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  })

  rl.question("login: ", (login) => {
    rl.question("password: ", (passwd) => {
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

  sock.on("connect", () => {
    var client = new NSClient()
    sock.pipe(client).pipe(sock)

    client.on("line", (line) => {
      console.log("<" + line)
    })

    client.on("pushLine", (line) => {
      console.log(">" + line)
    })

    client.on("salut", (data) => {
      client.doAuthentication(login, passwd).then(() => {
        console.log("[Info] Authentication OK.")
        client.sendState("actif")
      }).catch((err) => {
        console.error("[Error]" + err)
        client.sendExit()
      })
    })

    client.once("exit", () => {
      console.log("[Info] Connection closed.")
    })

    client.on("userCmdMsg", (sender, msg, dests) => {
      console.log(["[", sender.login, "@", sender.location, "] ", msg].join())
    })
  })

  sock.once("error", (err) => {
    console.error("CATCH ERROR")
    console.error(err)
  })
}

main()
