const { expect } = require("chai")
const {
  bsv,
  buildContractClass,
  toHex,
  getPreimage,
  num2bin,
  SigHashPreimage,
  OpCodeType,
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
const { num2bin: bigNum2bin } = require("pmutils").hex
const { generatePrivKey, privKeyToPubKey, sign } = require("rabinsig")
const { decimalToHexString } = require("rabinsig/src/utils")

const Token = buildContractClass(compileContract("predictionMarket.scrypt"))

describe("Test sCrypt contract merkleToken In Javascript", () => {
  const Signature = bsv.crypto.Signature
  const sighashType = Signature.SIGHASH_ANYONECANPAY | Signature.SIGHASH_SINGLE | Signature.SIGHASH_FORKID

  const privateKey = new bsv.PrivateKey.fromRandom("testnet")
  const publicKey = bsv.PublicKey.fromPrivateKey(privateKey)
  const pubKeyHex = toHex(publicKey)
  const pkh = bsv.crypto.Hash.sha256ripemd160(publicKey.toBuffer())
  const changePKH = toHex(pkh) // Needs to be unprefixed address
  const payoutPKH = changePKH

  const satScaling = 2 ** 20
  const lmsrHashes = getLmsrShas()

  const priv1 = generatePrivKey()
  const priv2 = generatePrivKey()
  const pub1 = privKeyToPubKey(priv1.p, priv1.q)
  const pub2 = privKeyToPubKey(priv2.p, priv2.q)
  const pub1Hex = bigNum2bin(pub1, 125)
  const pub2Hex = bigNum2bin(pub2, 125)
  const miner1Votes = 40
  const miner2Votes = 60
  const minerPubs = [pub1Hex, num2bin(miner1Votes, 1), pub2Hex, num2bin(miner2Votes, 1)].join("")

  let token, lockingScriptCodePart, tx_

  function testAddEntry(liquidity, sharesFor, sharesAgainst, globalLiquidity, globalSharesFor, globalSharesAgainst) {
    const newEntry = toHex(pubKeyHex + num2bin(liquidity, 1) + num2bin(sharesFor, 1) + num2bin(sharesAgainst, 1))
    const newLeaf = sha256(newEntry)

    const lastEntry = toHex("00".repeat(20) + "00" + "01" + "00")
    const lastLeaf = sha256(lastEntry)
    const lastMerklePath = lastLeaf + "01"

    const prevSharesStatus = num2bin(globalLiquidity, 1) + num2bin(globalSharesFor, 1) + num2bin(globalSharesAgainst, 1)

    const newLiquidity = globalLiquidity + liquidity
    const newSharesFor = globalSharesFor + sharesFor
    const newSharesAgainst = globalSharesAgainst + sharesAgainst
    const newSharesStatus = num2bin(newLiquidity, 1) + num2bin(newSharesFor, 1) + num2bin(newSharesAgainst, 1)

    const prevBalanceTableRoot = sha256(sha256(lastEntry).repeat(2))
    const newBalanceTableRoot = sha256(sha256(lastEntry) + sha256(newEntry))
    const newStatus = "00" + "00" + newSharesStatus + newBalanceTableRoot
    const prevStatus = "00" + "00" + prevSharesStatus + prevBalanceTableRoot
    const newLockingScript = [lockingScriptCodePart, newStatus].join(" ")

    const inputSatoshis = 6000000 // Ca 10 USD
    const satScalingAdjust = scalingFactor / satScaling
    const prevLmsrBalance = Math.round(lmsr(globalLiquidity, globalSharesFor, globalSharesAgainst) * scalingFactor)
    const newLmsrBalance = Math.round(lmsr(newLiquidity, newSharesFor, newSharesAgainst) * scalingFactor)
    const prevSatBalance = Math.floor(prevLmsrBalance / satScalingAdjust)
    const newSatBalance = Math.floor(newLmsrBalance / satScalingAdjust)
    const cost = newSatBalance - prevSatBalance
    const changeSats = inputSatoshis - cost
    // console.log("in: ", prevSatBalance)
    // console.log("out: ", newSatBalance)
    // console.log("change: ", changeSats)

    const prevLmsrMerklePath = getMerklePath(getPos(globalLiquidity, globalSharesFor, globalSharesAgainst), lmsrHashes)
    const newLmsrMerklePath = getMerklePath(getPos(newLiquidity, newSharesFor, newSharesAgainst), lmsrHashes)

    token.setDataPart(prevStatus)

    tx_.addInput(
      new bsv.Transaction.Input({
        prevTxId: dummyTxId,
        outputIndex: 0,
        script: ""
      }),
      bsv.Script.fromASM(token.lockingScript.toASM()),
      prevSatBalance
    )

    // token output
    tx_.addOutput(
      new bsv.Transaction.Output({
        script: bsv.Script.fromASM(newLockingScript),
        satoshis: newSatBalance
      })
    )

    const preimage = getPreimage(tx_, token.lockingScript.toASM(), prevSatBalance, inputIndex, sighashType)

    token.txContext = { tx: tx_, inputIndex, inputSatoshis: prevSatBalance }

    const result = token
      .addEntry(
        new SigHashPreimage(toHex(preimage)),
        liquidity,
        sharesFor,
        sharesAgainst,
        new Ripemd160(changePKH),
        new PubKey(pubKeyHex),
        changeSats,
        newLmsrBalance,
        new Bytes(newLmsrMerklePath),
        new Bytes(lastEntry),
        new Bytes(lastMerklePath)
      )
      .verify()

    // console.log(tx_.toString())
    // console.log(toHex(preimage))
    // console.log(prevSharesStatus + prevBalanceTableRoot)
    // console.log(prevSatBalance)

    // console.log(liquidity)
    // console.log(sharesFor)
    // console.log(sharesAgainst)
    // console.log(changePKH)
    // console.log(payoutPKH)
    // console.log(changeSats)
    // console.log(newLmsrBalance)
    // console.log(newLmsrMerklePath)
    // console.log(lastEntry)
    // console.log(lastMerklePath)

    return result
  }

  function testUpdateEntry(
    liquidity,
    sharesFor,
    sharesAgainst,
    prevLiquidity,
    prevSharesFor,
    prevSharesAgainst,
    globalLiquidity,
    globalSharesFor,
    globalSharesAgainst
  ) {
    const newEntry = toHex(pubKeyHex + num2bin(liquidity, 1) + num2bin(sharesFor, 1) + num2bin(sharesAgainst, 1))
    const newLeaf = sha256(newEntry)

    const prevEntry = toHex(
      pubKeyHex + num2bin(prevLiquidity, 1) + num2bin(prevSharesFor, 1) + num2bin(prevSharesAgainst, 1)
    )
    const prevLeaf = sha256(prevEntry)
    const merklePath = prevLeaf + "01"

    const prevSharesStatus = num2bin(globalLiquidity, 1) + num2bin(globalSharesFor, 1) + num2bin(globalSharesAgainst, 1)

    const liquidityChange = liquidity - prevLiquidity
    const sharesForChange = sharesFor - prevSharesFor
    const sharesAgainstChange = sharesAgainst - prevSharesAgainst

    const newGlobalLiquidity = globalLiquidity + liquidityChange
    const newGlobalSharesFor = globalSharesFor + sharesForChange
    const newGlobalSharesAgainst = globalSharesAgainst + sharesAgainstChange
    const newSharesStatus =
      num2bin(newGlobalLiquidity, 1) + num2bin(newGlobalSharesFor, 1) + num2bin(newGlobalSharesAgainst, 1)

    const prevBalanceTableRoot = sha256(sha256(prevEntry).repeat(2))
    const newBalanceTableRoot = sha256(sha256(newEntry).repeat(2))
    const newStatus = "00" + "00" + newSharesStatus + newBalanceTableRoot
    const prevStatus = "00" + "00" + prevSharesStatus + prevBalanceTableRoot
    const newLockingScript = [lockingScriptCodePart, newStatus].join(" ")

    const inputSatoshis = 6000000 // Ca 10 USD
    const satScalingAdjust = scalingFactor / satScaling
    const prevLmsrBalance = Math.round(lmsr(globalLiquidity, globalSharesFor, globalSharesAgainst) * scalingFactor)
    const newLmsrBalance = Math.round(
      lmsr(newGlobalLiquidity, newGlobalSharesFor, newGlobalSharesAgainst) * scalingFactor
    )
    const prevSatBalance = Math.floor(prevLmsrBalance / satScalingAdjust)
    const newSatBalance = Math.floor(newLmsrBalance / satScalingAdjust)
    const cost = newSatBalance - prevSatBalance
    const changeSats = inputSatoshis - cost
    // console.log("in: ", prevSatBalance)
    // console.log("out: ", newSatBalance)
    // console.log("change: ", changeSats)

    // return true

    const prevLmsrMerklePath = getMerklePath(getPos(globalLiquidity, globalSharesFor, globalSharesAgainst), lmsrHashes)
    const newLmsrMerklePath = getMerklePath(
      getPos(newGlobalLiquidity, newGlobalSharesFor, newGlobalSharesAgainst),
      lmsrHashes
    )

    token.setDataPart(prevStatus)

    tx_.addInput(
      new bsv.Transaction.Input({
        prevTxId: dummyTxId,
        outputIndex: 0,
        script: ""
      }),
      bsv.Script.fromASM(token.lockingScript.toASM()),
      prevSatBalance
    )

    // token output
    tx_.addOutput(
      new bsv.Transaction.Output({
        script: bsv.Script.fromASM(newLockingScript),
        satoshis: newSatBalance
      })
    )

    const preimage = getPreimage(tx_, token.lockingScript.toASM(), prevSatBalance, inputIndex, sighashType)

    token.txContext = { tx: tx_, inputIndex, inputSatoshis: prevSatBalance }

    sig = signTx(tx_, privateKey, token.lockingScript.toASM(), prevSatBalance, inputIndex, sighashType)

    const result = token
      .updateEntry(
        new SigHashPreimage(toHex(preimage)),
        liquidity,
        sharesFor,
        sharesAgainst,
        prevLiquidity,
        prevSharesFor,
        prevSharesAgainst,
        new Ripemd160(changePKH),
        new PubKey(pubKeyHex),
        new Sig(toHex(sig)),
        changeSats,
        newLmsrBalance,
        new Bytes(newLmsrMerklePath),
        new Bytes(merklePath)
      )
      .verify()

    // console.log(tx_.toString())
    // console.log(toHex(preimage))
    // console.log(prevSharesStatus + prevBalanceTableRoot)
    // console.log(prevSatBalance)

    // console.log(liquidity)
    // console.log(sharesFor)
    // console.log(sharesAgainst)
    // console.log(changePKH)
    // console.log(payoutPKH)
    // console.log(changeSats)
    // console.log(newLmsrBalance)
    // console.log(newLmsrMerklePath)
    // console.log(lastEntry)
    // console.log(lastMerklePath)

    return result
  }

  beforeEach(() => {
    tx_ = new bsv.Transaction()
    token = new Token(new Bytes(minerPubs))

    lockingScriptCodePart = token.codePart.toASM()
  })

  it("should buy token", () => {
    result = testAddEntry(0, 1, 0, 1, 1, 1)
    expect(result.success, result.error).to.be.true
  })

  it("should buy multiple tokens", () => {
    result = testAddEntry(0, 2, 0, 1, 1, 1)
    expect(result.success, result.error).to.be.true
  })

  it("should add liquidity", () => {
    result = testAddEntry(1, 0, 0, 1, 2, 1)
    expect(result.success, result.error).to.be.true
  })

  it("should buy more tokens", () => {
    result = testUpdateEntry(0, 2, 0, 0, 1, 0, 1, 1, 1)
    expect(result.success, result.error).to.be.true
  })

  it("should sell tokens", () => {
    result = testUpdateEntry(0, 0, 0, 0, 1, 0, 1, 1, 1)
    expect(result.success, result.error).to.be.true
  })

  it("should sell more tokens", () => {
    result = testUpdateEntry(0, 1, 0, 1, 2, 1, 3, 2, 3)
    expect(result.success, result.error).to.be.true
  })

  it("should sell all tokens", () => {
    result = testUpdateEntry(0, 0, 0, 0, 2, 0, 1, 2, 5)
    expect(result.success, result.error).to.be.true
  })

  it("should verify signatures", () => {
    const inputSatoshis = 6000000
    const vote = 1
    const sig1 = sign(num2bin(vote, 1), priv1.p, priv1.q, pub1)
    const sig2 = sign(num2bin(vote, 1), priv2.p, priv2.q, pub2)
    const sig1Hex = bigNum2bin(sig1.signature, 125)
    const sig2Hex = bigNum2bin(sig2.signature, 125)

    const minerSigs = [
      num2bin(0, 1),
      sig1Hex,
      num2bin(sig1.paddingByteCount, 1),
      num2bin(1, 1),
      sig2Hex,
      num2bin(sig2.paddingByteCount, 1)
    ].join("")

    const newOpReturn = "01" + "01" + "00".repeat(35)
    const newLockingScript = [lockingScriptCodePart, newOpReturn].join(" ")

    token.setDataPart("00".repeat(37))

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
        satoshis: inputSatoshis
      })
    )

    const preimage = getPreimage(tx_, token.lockingScript.toASM(), inputSatoshis, inputIndex, sighashType)

    token.txContext = { tx: tx_, inputIndex, inputSatoshis }

    // console.log(minerPubs)
    // console.log(toHex(preimage))
    // console.log(vote)
    // console.log(minerSigs)
    // console.log(tx_.toString())
    // console.log("00".repeat(37))

    const result = token.decide(new SigHashPreimage(toHex(preimage)), vote, new Bytes(minerSigs)).verify()
    expect(result.success, result.error).to.be.true
  })

  it("should verify partial signatures", () => {
    const inputSatoshis = 6000000
    const vote = 1
    const sig1 = sign(num2bin(vote, 1), priv1.p, priv1.q, pub1)
    const sig2 = sign(num2bin(vote, 1), priv2.p, priv2.q, pub2)
    const sig1Hex = bigNum2bin(sig1.signature, 125)
    const sig2Hex = bigNum2bin(sig2.signature, 125)

    const minerSigs = [num2bin(1, 1), sig2Hex, num2bin(sig2.paddingByteCount, 1)].join("")

    const newOpReturn = "01" + "01" + "00".repeat(35)
    const newLockingScript = [lockingScriptCodePart, newOpReturn].join(" ")

    token.setDataPart("00".repeat(37))

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
        satoshis: inputSatoshis
      })
    )

    const preimage = getPreimage(tx_, token.lockingScript.toASM(), inputSatoshis, inputIndex, sighashType)

    token.txContext = { tx: tx_, inputIndex, inputSatoshis }

    // console.log(minerPubs)
    // console.log(toHex(preimage))
    // console.log(vote)
    // console.log(minerSigs)
    // console.log(tx_.toString())
    // console.log("00".repeat(37))

    const result = token.decide(new SigHashPreimage(toHex(preimage)), vote, new Bytes(minerSigs)).verify()
    expect(result.success, result.error).to.be.true
  })

  it("should not verify insufficient signatures", () => {
    const inputSatoshis = 6000000
    const vote = 1
    const sig1 = sign(num2bin(vote, 1), priv1.p, priv1.q, pub1)
    const sig2 = sign(num2bin(vote, 1), priv2.p, priv2.q, pub2)
    const sig1Hex = bigNum2bin(sig1.signature, 125)
    const sig2Hex = bigNum2bin(sig2.signature, 125)

    const minerSigs = [num2bin(0, 1), sig1Hex, num2bin(sig1.paddingByteCount, 1)].join("")

    const newOpReturn = "01" + "01" + "00".repeat(35)
    const newLockingScript = [lockingScriptCodePart, newOpReturn].join(" ")

    token.setDataPart("00".repeat(37))

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
        satoshis: inputSatoshis
      })
    )

    const preimage = getPreimage(tx_, token.lockingScript.toASM(), inputSatoshis, inputIndex, sighashType)

    token.txContext = { tx: tx_, inputIndex, inputSatoshis }

    // console.log(minerPubs)
    // console.log(toHex(preimage))
    // console.log(vote)
    // console.log(minerSigs)
    // console.log(tx_.toString())
    // console.log("00".repeat(37))

    const result = token.decide(new SigHashPreimage(toHex(preimage)), vote, new Bytes(minerSigs)).verify()
    expect(result.success, result.error).to.be.false
  })
})
