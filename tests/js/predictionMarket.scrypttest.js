const { expect } = require("chai")
const {
  bsv,
  buildContractClass,
  toHex,
  getPreimage,
  num2bin,
  SigHashPreimage,
  Ripemd160,
  Sig,
  Bytes,
  PubKey,
  signTx
} = require("scryptlib")
const { inputIndex, tx, compileContract, dummyTxId } = require("../../helper")
const { sha256 } = require("pmutils").sha
const { scalingFactor, lmsr, getLmsrShas, getPos } = require("pmutils").lmsr
const { getMerklePath } = require("pmutils").merkleTree

describe("Test sCrypt contract merkleToken In Javascript", () => {
  const Signature = bsv.crypto.Signature
  const sighashType = Signature.SIGHASH_ANYONECANPAY | Signature.SIGHASH_ALL | Signature.SIGHASH_FORKID

  const privateKey = new bsv.PrivateKey.fromRandom("testnet")
  const publicKey = bsv.PublicKey.fromPrivateKey(privateKey)
  const pkh = bsv.crypto.Hash.sha256ripemd160(publicKey.toBuffer())
  const changePKH = toHex(pkh) // Needs to be unprefixed address
  const payoutPKH = changePKH

  const satScaling = 2 ** 20
  const lmsrHashes = getLmsrShas()

  const Token = buildContractClass(compileContract("predictionMarket.scrypt"))

  let token, lockingScriptCodePart, tx_

  beforeEach(() => {
    tx_ = new bsv.Transaction()
    token = new Token()

    lockingScriptCodePart = token.codePart.toASM()
  })

  it("should buy token", () => {
    const sharesFor = 1
    const sharesAgainst = 0

    const newEntry = toHex(payoutPKH + num2bin(sharesFor, 1) + num2bin(sharesAgainst, 1))
    const newLeaf = sha256(newEntry)

    const lastEntry = toHex("00".repeat(20) + "01" + "00")
    const lastLeaf = sha256(lastEntry)
    const lastMerklePath = sha256(lastEntry) + "01"

    const liquidity = 1
    const globalSharesFor = 1
    const globalSharesAgainst = 1
    const prevSharesStatus = num2bin(liquidity, 1) + num2bin(globalSharesFor, 1) + num2bin(globalSharesAgainst, 1)

    const newSharesFor = globalSharesFor + sharesFor
    const newSharesAgainst = globalSharesAgainst + sharesAgainst
    const newSharesStatus = num2bin(liquidity, 1) + num2bin(newSharesFor, 1) + num2bin(newSharesAgainst, 1)

    const prevBalanceTableRoot = sha256(sha256(lastEntry).repeat(2))
    const newBalanceTableRoot = sha256(sha256(lastEntry) + sha256(newEntry))
    const newLockingScript = lockingScriptCodePart + " OP_RETURN " + newSharesStatus + newBalanceTableRoot

    const inputSatoshis = 6000000 // Ca 10 USD
    const satScalingAdjust = scalingFactor / satScaling
    const prevLmsrBalance = Math.round(lmsr(liquidity, globalSharesFor, globalSharesAgainst) * scalingFactor)
    const newLmsrBalance = Math.round(lmsr(liquidity, newSharesFor, newSharesAgainst) * scalingFactor)
    const prevSatBalance = Math.round(prevLmsrBalance / satScalingAdjust)
    const newSatBalance = Math.round(newLmsrBalance / satScalingAdjust)
    const cost = newSatBalance - prevSatBalance
    const changeSats = inputSatoshis - cost

    const prevLmsrMerklePath = getMerklePath(getPos(liquidity, globalSharesFor, globalSharesAgainst), lmsrHashes)
    const newLmsrMerklePath = getMerklePath(getPos(liquidity, newSharesFor, newSharesAgainst), lmsrHashes)

    token.dataLoad = prevSharesStatus + prevBalanceTableRoot

    tx_.addInput(
      new bsv.Transaction.Input({
        prevTxId: dummyTxId,
        outputIndex: 0,
        script: ""
      }),
      bsv.Script.fromASM(token.lockingScript.toASM()),
      inputSatoshis
    )

    // token output
    tx_.addOutput(
      new bsv.Transaction.Output({
        script: bsv.Script.fromASM(newLockingScript),
        satoshis: inputSatoshis + cost
      })
    )

    // change output
    tx_.addOutput(
      new bsv.Transaction.Output({
        script: bsv.Script.buildPublicKeyHashOut(publicKey.toAddress()),
        satoshis: changeSats
      })
    )

    const preimage = getPreimage(tx_, token.lockingScript.toASM(), inputSatoshis, inputIndex, sighashType)

    token.txContext = { tx: tx_, inputIndex, inputSatoshis }
    const result = token
      .buy(
        new SigHashPreimage(toHex(preimage)),
        sharesFor,
        sharesAgainst,
        new Ripemd160(changePKH),
        new Ripemd160(payoutPKH),
        changeSats,
        prevLmsrBalance,
        newLmsrBalance,
        new Bytes(prevLmsrMerklePath),
        new Bytes(newLmsrMerklePath),
        new Bytes(lastEntry),
        new Bytes(lastMerklePath)
      )
      .verify()

    expect(result.success, result.error).to.be.true
  })
})
