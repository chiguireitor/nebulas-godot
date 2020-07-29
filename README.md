Nebulas-Godot
====

A Godot 3.2+ compatible module to enable your games to use Nebulas-powered tokens and smart contracts.

Usage Tutorial: https://github.com/chiguireitor/nebulas-sample

Done with funding thanks to [Go Nebulas project 293](https://go.nebulas.io/project/293), a proposal created by the Nebulas community to further the Nebulas reach into gaming.

Usage
==

The `Nebulas` class contains all the necessary methods to create addresses, transactions and contract calls on Nebulas. An example wallet manager Singleton is included in the `scripts` directory.

Precompiled binaries can be found in the Nebulas site. If you need to use additional modules follow the next paragraph.

Copy the `modules` and `thirdparty` directories into your Godot build directory. Build following Godot's guides.

GDNative
==

Some work has been made towards making this module be available by compiling it as a GDNative module, however, Godot doesn't exposes several parts of its internal definitions that are vital for any cryptocurrency based game.

Adapting this module to a GDNative could be done in the future, along with the QRCode module that is needed by most wallets.

License
==

Read LICENSE

tl;dr: MIT Licensed
