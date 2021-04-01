const { expect } = require("chai")
const { buildContractClass } = require("scryptlib")

const { compileContract } = require("../../helper")

describe("Test sCrypt contract fixMath In Javascript", () => {
  let result, fixMath

  before(() => {
    const FixMath = buildContractClass(compileContract("testFixMath.scrypt"))
    fixMath = new FixMath()
  })

  it("should return true", () => {
    result = fixMath.testLog(1).verify()
    expect(result.success, result.error).to.be.true
    result = fixMath.testExp(1).verify()
    expect(result.success, result.error).to.be.true
  })
})
