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
| [`bitcoin-utils`](bitcoin-utils) | Helper package containing the implementation of certain fundamental operations and debugging functions. |
| [`bitcoin-testscripts`](bitcoin-testscripts) | A collection of test scripts for testing BitVM2 concept. |
| [`bitcoin-scriptexec`](bitcoin-scriptexec) | A helper crate for executing Bitcoin scripts. Fork of [BitVM package](https://github.com/BitVM/rust-bitcoin-scriptexec). |

## Setting up a Local Bitcoin Node

```shell
docker compose up -d
```

> [!WARNING]
>
> Sometimes Docker Compose may fail at step of creating the volumes,
> the most simple solution is, in regards of failure, just trying
> starting it again several times until it works.

Let us create a temporary alias for `bitcoin-cli` from the container like this:

```shell
alias bitcoin-cli="docker compose exec bitcoind bitcoin-cli"
```

Create a fresh wallet for your user:

```shell
bitcoin-cli createwallet "my"
```

> [!WARNING]
>
> Do not create more than one wallet, otherwise further steps would
> require a bit of modification.

Generate fresh address and store it to environmental variable:

```shell
export ADDRESS=$(bitcoin-cli -rpcwallet="my" getnewaddress "main" "bech32")
```

Then mine 101 blocks to your address:

```shell
bitcoin-cli generatetoaddress 101 $ADDRESS
```

> [!NOTE]
>
> Rewards for mined locally blocks will go to this address, but, by
> protocol rules, BTCs are mature only after 100 confirmations, so
> that's why 101 blocks are mined. You can see other in `immature`
> balances fields, after executing next command.
>
> For more info about Bitcoin RPC API see [^2].

```shell
bitcoin-cli -rpcwallet="my" getbalances
```

## Working with `nero-cli`

Compile `nero-cli`:

```shell
cargo install --path ./nero-cli
```

Generate random pair of keys for payout path spending:

```shell
nero-cli --config ./nero.toml generate-keys
```

Possible output:

```shell
abffe139daab7e63742643886728755f08288f5d05fb6a0aebc3f3ff41d1d83c
02dedae18ba57d264289ae13f9009ba4ff62d006d8a64078724a5f153c8f7cca71
```

Generate some random input for script:

```shell
nero-cli --config ./nero.toml generate-input
```

Now you got a generated script input in `input.txt` file in hex format
and in Bitcoin script in stdout, for example output could be:

```
OP_PUSHBYTES_3 f4531f OP_PUSHBYTES_4 5bca4206 OP_PUSHBYTES_4 d3d2de1f OP_PUSHBYTES_4 831e530e OP_PUSHBYTES_4 35364014 OP_PUSHBYTES_4 c54c6802 OP_PUSHBYTES_4 be8eaa14 OP_PUSHBYTES_4 1907b201 OP_PUSHBYTES_4 9eb1a719 OP_PUSHBYTES_3 f4531f OP_PUSHBYTES_4 5bca4206 OP_PUSHBYTES_4 d3d2de1f OP_PUSHBYTES_4 831e530e OP_PUSHBYTES_4 35364014 OP_PUSHBYTES_4 c54c6802 OP_PUSHBYTES_4 be8eaa14 OP_PUSHBYTES_4 1907b201 OP_PUSHBYTES_4 9eb1a719
```

### Payout path spending

Now, let's generate and send assert transaction:

```shell
nero-cli --config ./nero.toml assert-tx --input ./input.txt --amount 0.007BTC --pubkey dedae18ba57d264289ae13f9009ba4ff62d006d8a64078724a5f153c8f7cca71
```

This could take a while for fibonachi sequence. You'll then get a
transaction id:

```shell
a35153ff68d3fce1fd1f270c4a3a3ef1f1fb1703055c03f6b5b1fef9d08f50ee:0
```

> And all disprove scripts in `disproves` directories with payout script
> in `payout.txt`.


Which you could fetch and check:

```shell
bitcoin-cli getrawtransaction A35153ff68d3fce1fd1f270c4a3a3ef1f1fb1703055c03f6b5b1fef9d08f50ee
```

Then convert it from hex to JSON:

```shell
bitcoin-cli decoderawtransaction 020000000001014754bb8d55fb1a9dcf2380c7011eed1601e3c070aeb9f2481f0c28e322199ac90100000000fdffffff0260ae0a0000000000225120d75e8e13e5467b03ea564f8f60c9acdc0859a320bf5359c2accd20e34cbb73ec67c94704000000002251203d8f7c4be893b12bd0a81aa99dd313f01f6cde1eca6ce67d2b029c940b5c804c0140b045b92d05c9b78ca58bc7402650bf8bac49a06b8d85991ca841fff95e1f21ed3f40c5ec84a966dc824b0a706ec8de8e2f5fa0f754ded8c27e1162aaa86d861700000000
```

Let's spend it by payout transaction. To pass the default locktime of
two weeks, we need to mine 2017 blocks:

```shell
bitcoin-cli generatetoaddress 2017 $ADDRESS &> /dev/null
```

And then spend it:

```shell
nero-cli --config ./nero.toml spend-payout --assert a35153ff68d3fce1fd1f270c4a3a3ef1f1fb1703055c03f6b5b1fef9d08f50ee:0 --seckey Abffe139daab7e63742643886728755f08288f5d05fb6a0aebc3f3ff41d1d83c --address $ADDRESS
```

Output:

```shell
7bb040e609cc1acababfb17a50b6c48646c28d5afdcbb45cf33dca1e69542d2a
```

### Disprove spending

```shell
nero-cli --config ./nero.toml assert-tx --input ./input.txt --amount 0.007BTC --pubkey dedae18ba57d264289ae13f9009ba4ff62d006d8a64078724a5f153c8f7cca71 --address $ADDRESS --distort
```

Output:

```shell
11283f38271775b6250ce97d9f633a6977f4318625ab7ea4d36b8535e7c2c692:0 # <-- assert tx out
445 # <-- spendable disprove script (because of invalid states)
```

And let's spend it using disprove script from local directory
`disproves` by number:

```shell
nero-cli --config ./nero.toml spend-disprove --assert 11283f38271775b6250ce97d9f633a6977f4318625ab7ea4d36b8535e7c2c692:0 --address $ADDRESS --disprove 445
```

[^1]: https://bitvm.org/bitvm_bridge.pdf
[^2]: https://developer.bitcoin.org/reference/rpc/
