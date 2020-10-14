const { expect } = require("chai")
const { buildContractClass, Bytes } = require("scryptlib")
const { compileContract } = require("../../helper")
const { getMerklePath, getMerkleRoot } = require("pmutils").merkleTree
const { lmsr, scalingFactor, getPos, getLmsrShas, getLmsrHex } = require("pmutils").lmsr
const { num2bin } = require("pmutils").hex

describe("Test lmsr utils In Javascript", () => {
  let result, testLmsr

  before(() => {
    const LMSR = buildContractClass(compileContract("testLmsr.scrypt"))
    testLmsr = new LMSR()
  })

  it("should return true", () => {
    const lmsrHashes = getLmsrShas()
    const l = 1
    const n = 1
    const m = 1
    const cost = Math.round(lmsr(l, n, m) * scalingFactor)
    const merklePath = getMerklePath(getPos(l, n, m), lmsrHashes)

    // console.log(getMerkleRoot(lmsrHashes))
    // console.log(getLmsrHex(l, n, m, cost))
    // console.log(cost)

    result = testLmsr.validate(l, n, m, cost, new Bytes(merklePath)).verify()
    expect(result.success, result.error).to.be.true
  })
})
