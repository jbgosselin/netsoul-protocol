#!/usr/bin/env coffee
net = require "net"
readline = require "readline"
NSClient = require "./lib/index"
NS_HOST = "ns-server.epita.fr"
NS_PORT = 4242

main = () ->
  rl = readline.createInterface
    input: process.stdin
    output: process.stdout

  rl.question "login: ", (login) ->
    rl.question "password: ", (passwd) ->
      connect login, passwd
      rl.close()

connect = (login, passwd) ->
  sock = net.createConnection NS_PORT, NS_HOST

  sock.on "connect", () ->
    client = new NSClient()

    sock.pipe(client).pipe sock

    client.on "line", (line) -> console.log "<#{line}"

    client.on "pushLine", (line) -> console.log ">#{line}"

    client.on "salut", (data) ->
      client.doAuthentication login, passwd
      .then () ->
        console.log "[Info] Authentication OK."
        client.sendState "actif"
      , (err) ->
        console.error "[Error] #{err}"
        client.sendExit()

    client.once "exit", () -> console.log "[Info] Connection closed."

    client.on "userCmdMsg", (sender, msg, dests) -> console.log "[#{sender.login}@#{sender.location}] #{msg}"

  sock.once "error", (err) ->
    console.error "CATCH ERROR"
    console.error err

main()
