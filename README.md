<div align="center">
<h1> Nero: BitVM2 Made Practical </h1>
</div>

<p align="center">
  <img width="25%" src="./docs/images/icon.png">
</p>

Practical implementation of the BitVM2 protocol by Distributed Lab. You can check the 
[original BitVM2 paper](https://bitvm.org/bitvm_bridge.pdf) and
[our implementation paper](./docs/paper/nero.pdf) for more details).

> [!IMPORTANT]
>
> This project is under heavy development and API can drastically vary due to its early development stage.
> We do not guarantee any backward compatibility until the first release and recommend using it with great caution.

## :file_folder: Contents

The project contains multiple crates:

| Crate | Description |
| --- | --- |
| [`bitcoin-splitter`](bitcoin-splitter/README.md) | A crate for splitting the Bitcoin script into multiple parts as suggested by the recent [^1]). |
| [`bitcoin-winternitz`](bitcoin-winternitz) | Winternitz Signature and recovery implementation based on BitVM's [`[signatures]`](https://github.com/BitVM/BitVM/tree/main/src/signatures) package. |
| [`bitcoin-utils`](bitcoin-utils) | Helper package containing implementation of certain fundamental operations and debugging functions. |
| [`bitcoin-testscripts`](bitcoin-testscripts) | A collection of test scripts for testing BitVM2 concept. |
| [`bitcoin-scriptexec`](bitcoin-scriptexec) | A helper crate for executing Bitcoin scripts. Fork of [BitVM package](https://github.com/BitVM/rust-bitcoin-scriptexec). |

## Setting up a Local Bitcoin Node

```shell
docker compose up -d
```

> [!WARNING]
> Sometimes Docker Compose may fail at step of creating the volumes, the most simple solution is, in regards of failure, just trying starting it again several times until it works.

Let us create a temporary alias for `bitcoin-cli` from the container like this:

```shell
alias bitcoin-cli="docker compose exec bitcoind bitcoin-cli"
```

Create a fresh wallet for your user:

```shell
bitcoin-cli createwallet "my"
```

> [!WARNING]
> Do not create more than one wallet, otherwise further steps would require
> a bit of modification.

Generate fresh address and store it to environmental variable:

```shell
export ADDRESS=$(bitcoin-cli getnewaddress "main" "bech32")
```

Then mine 101 blocks to your address:

```shell
bitcoin-cli generatetoaddress 101 $ADDRESS
```

> [!NOTE]
> Rewards for mined locally blocks will go to this address, but, by protocol rules, BTCs are mature only after 100 confirmations, so that's why 101 blocks are mined. You can see other in  `immature` balances fields, after executing next command.
>
> For more info about Bitcoin RPC API see [^2].

```shell
bitcoin-cli getbalances
```

[^1]: https://bitvm.org/bitvm_bridge.pdf
[^2]: https://developer.bitcoin.org/reference/rpc/
