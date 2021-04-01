const { expect } = require("chai")
const { buildContractClass } = require("scryptlib")

const { compileContract } = require("../../helper")

describe("Test sCrypt contract fixMath In Javascript", () => {
  let result, fixLmsr

  before(() => {
    const FixLmsr = buildContractClass(compileContract("testFixLmsr.scrypt"))
    fixLmsr = new FixLmsr()
  })

  it("should return true", () => {
    result = fixLmsr.test(1).verify()
    expect(result.success, result.error).to.be.true
  })
})
