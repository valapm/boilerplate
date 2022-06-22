const { expect } = require("chai")
const { buildContractClass, Bytes } = require("scryptlib")

const { compileContract } = require("../../helper")

describe("Test sCrypt contract fixMath In Javascript", () => {
  let result, fixLmsr

  before(() => {
    const contract = require("../../out/testFixLmsr_debug_desc.json")
    console.log(contract.contract)
    const FixLmsr = buildContractClass(contract)
    fixLmsr = new FixLmsr()
  })

  it("should return true", () => {
    result = fixLmsr.test(1).verify()
    expect(result.success, result.error).to.be.true
  })
})
