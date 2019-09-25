const { assertRevert } = require('./helpers/helpers')
const Oracle = artifacts.require('TokenBalanceOracle')
const MockErc20 = artifacts.require('TokenMock')
const ExecutionTarget = artifacts.require('ExecutionTarget')

const deployDAO = require('./helpers/deployDao')
const { deployedContract } = require('./helpers/helpers')
const { hash: nameHash } = require('eth-ens-namehash')
const BN = require('bn.js')

const ANY_ADDR = '0xffffffffffffffffffffffffffffffffffffffff'

const ORACLE_PARAM_ID = new BN(203).shln(248)
const EQ = new BN(1).shln(240)

contract('TokenBalanceOracle', ([appManager, account1, account2, ...accounts]) => {
  let oracleBase, oracle, mockErc20, executionTargetBase, executionTarget
  let SET_TOKEN_ROLE, SET_BALANCE_ROLE, SET_COUNTER_ROLE, DECREASE_COUNTER_ROLE, INCREASE_COUNTER_ROLE

  const MOCK_TOKEN_BALANCE = 1000
  const account1Balance = 50
  const ORACLE_MINIMUM_BALANCE = 100

  before('deploy base apps', async () => {
    oracleBase = await Oracle.new()
    SET_TOKEN_ROLE = await oracleBase.SET_TOKEN_ROLE()
    SET_BALANCE_ROLE = await oracleBase.SET_BALANCE_ROLE()

    executionTargetBase = await ExecutionTarget.new()
    SET_COUNTER_ROLE = await executionTargetBase.SET_COUNTER_ROLE()
    DECREASE_COUNTER_ROLE = await executionTargetBase.DECREASE_COUNTER_ROLE()
    INCREASE_COUNTER_ROLE = await executionTargetBase.INCREASE_COUNTER_ROLE()
  })

  beforeEach('deploy dao and token balance oracle', async () => {
    const daoDeployment = await deployDAO(appManager)
    dao = daoDeployment.dao
    acl = daoDeployment.acl

    const newOracleReceipt = await dao.newAppInstance(
      nameHash('token-balance-oracle.aragonpm.test'),
      oracleBase.address,
      '0x',
      false,
      {
        from: appManager,
      }
    )
    oracle = await Oracle.at(deployedContract(newOracleReceipt))
    mockErc20 = await MockErc20.new(appManager, MOCK_TOKEN_BALANCE)
    mockErc20.transfer(account1, account1Balance)
  })

  describe('initialize(address _token)', () => {
    beforeEach('initialize oracle', async () => {
      await oracle.initialize(mockErc20.address, ORACLE_MINIMUM_BALANCE)
    })

    it('sets variables as expected', async () => {
      const actualToken = await oracle.token()
      const hasInitialized = await oracle.hasInitialized()

      assert.strictEqual(actualToken, mockErc20.address)
      assert.isTrue(hasInitialized)
    })

    it('reverts on reinitialization', async () => {
      await assertRevert(oracle.initialize(mockErc20.address, ORACLE_MINIMUM_BALANCE), 'INIT_ALREADY_INITIALIZED')
    })

    describe('setToken(address _token)', () => {
      beforeEach('set permission', async () => {
        await acl.createPermission(appManager, oracle.address, SET_TOKEN_ROLE, appManager)
      })

      it('sets a new token', async () => {
        const newMockErc20 = await MockErc20.new(appManager, 100)
        const expectedToken = newMockErc20.address

        await oracle.setToken(expectedToken)

        const actualToken = await oracle.token()
        assert.equal(actualToken, expectedToken)
      })

      it('reverts when setting a non contract token address', async () => {
        await assertRevert(oracle.setToken(appManager), 'ORACLE_TOKEN_NOT_CONTRACT')
      })
    })

    describe('setBalance(uint256 _minBalance)', () => {
      beforeEach('set permission', async () => {
        await acl.createPermission(appManager, oracle.address, SET_BALANCE_ROLE, appManager)
      })

      it('sets a new minimum balance', async () => {
        const expectedNewBalance = 100
        await oracle.setBalance(expectedNewBalance)

        const actualNewBalance = await oracle.minBalance()
        assert.equal(actualNewBalance, expectedNewBalance)
      })
    })

    describe('canPerform(address, address, bytes32, uint256[])', () => {
      it(`can perform action if account  has a minimum balance of ${ORACLE_MINIMUM_BALANCE} tokens`, async () => {
        assert.isTrue(await oracle.canPerform(appManager, ANY_ADDR, '0x', []))
      })

      it(`can't perform action if account has less than ${ORACLE_MINIMUM_BALANCE} tokens`, async () => {
        assert.isFalse(await oracle.canPerform(account1, ANY_ADDR, '0x', []))
      })

      it("can't perform action if account does not have tokens", async () => {
        assert.isFalse(await oracle.canPerform(account2, ANY_ADDR, '0x', []))
      })

      describe('address passed as param', () => {
        it(`can perform action if account passed as param  has a minimum balance of  ${ORACLE_MINIMUM_BALANCE} tokens`, async () => {
          assert.isTrue(await oracle.canPerform(appManager, ANY_ADDR, '0x', [appManager]))
        })

        it(`can't perform action if account passed pas param has less than ${ORACLE_MINIMUM_BALANCE} tokens`, async () => {
          assert.isFalse(await oracle.canPerform(appManager, ANY_ADDR, '0x', [account1]))
        })

        it("can't perform action if account passed as param does not have tokens", async () => {
          assert.isFalse(await oracle.canPerform(appManager, ANY_ADDR, '0x', [account2]))
        })
      })

      describe('address and balance passed as params', () => {
        it('can perform action if account passed as param has more tokens than value passed as param', async () => {
          assert.isTrue(await oracle.canPerform(appManager, ANY_ADDR, '0x', [appManager, 950]))
        })

        it("can't perform action if account passed as param has less tokens than value passed as param", async () => {
          assert.isFalse(await oracle.canPerform(appManager, ANY_ADDR, '0x', [account1, 950]))
        })

        it("can't perform action if account passed as param does not have tokens", async () => {
          assert.isFalse(await oracle.canPerform(appManager, ANY_ADDR, '0x', [account2, 0]))
        })
      })
    })

    describe('integration tests with executionTarget', () => {
      let INITIAL_COUNTER = 1
      let oracleAddressBN, params

      beforeEach('deploy ExecutionTarget', async () => {
        const newExecutionTargetReceipt = await dao.newAppInstance(
          nameHash('execution-target.aragonpm.test'),
          executionTargetBase.address,
          '0x',
          false,
          {
            from: appManager,
          }
        )
        executionTarget = await ExecutionTarget.at(deployedContract(newExecutionTargetReceipt))

        //convert oracle address to BN and get param256: [(uint256(ORACLE_PARAM_ID) << 248) + (uint256(EQ) << 240) + oracleAddress];
        oracleAddressBN = new BN(oracle.address.slice(2), 16)
        params = [ORACLE_PARAM_ID.add(EQ).add(oracleAddressBN)]

        await executionTarget.initialize(INITIAL_COUNTER)
      })

      describe('executing function with no auth params', () => {
        beforeEach('Create role and grant with params', async () => {
          await acl.createPermission(appManager, executionTarget.address, SET_COUNTER_ROLE, appManager)
          await acl.grantPermissionP(appManager, executionTarget.address, SET_COUNTER_ROLE, params)
          await acl.grantPermissionP(account1, executionTarget.address, SET_COUNTER_ROLE, params)
          await acl.grantPermissionP(account2, executionTarget.address, SET_COUNTER_ROLE, params)
        })

        it(`can set counter if account has a minimum balance of ${ORACLE_MINIMUM_BALANCE} tokens`, async () => {
          const expectedCounter = 3

          await executionTarget.setCounter(expectedCounter)

          const actualCounter = await executionTarget.counter()
          assert.equal(actualCounter, expectedCounter)
        })

        it(`can't set counter if account has less than ${ORACLE_MINIMUM_BALANCE} tokens`, async () => {
          await assertRevert(executionTarget.setCounter(1, { from: account1 }), 'APP_AUTH_FAILED')
        })

        it("can't set counter if account does not have tokens", async () => {
          await assertRevert(executionTarget.setCounter(1, { from: account2 }), 'APP_AUTH_FAILED')
        })
      })

      describe('executing function with address auth param', () => {
        beforeEach('Create role and grant with params', async () => {
          await acl.createPermission(ANY_ADDR, executionTarget.address, DECREASE_COUNTER_ROLE, appManager)
          await acl.grantPermissionP(ANY_ADDR, executionTarget.address, DECREASE_COUNTER_ROLE, params)
        })

        it(`can decrease counter if account passed as param has a minimum balance of ${ORACLE_MINIMUM_BALANCE} tokens`, async () => {
          await executionTarget.decreaseCounter(appManager)

          const actualCounter = await executionTarget.counter()
          assert.equal(actualCounter, INITIAL_COUNTER - 1)
        })

        it(`can't decrease counter if account passed as param has less than ${ORACLE_MINIMUM_BALANCE} tokens`, async () => {
          await assertRevert(executionTarget.decreaseCounter(account1), 'APP_AUTH_FAILED')
        })

        it("can't decrease counter if account passed as param does not have tokens", async () => {
          await assertRevert(executionTarget.decreaseCounter(account2), 'APP_AUTH_FAILED')
        })
      })

      describe('executing function with address and balance auth params', () => {
        //note that for this function the required minimum balance is set by the counter state variable.
        beforeEach('Create role and grant with params', async () => {
          await acl.createPermission(ANY_ADDR, executionTarget.address, INCREASE_COUNTER_ROLE, appManager)
          await acl.grantPermissionP(ANY_ADDR, executionTarget.address, INCREASE_COUNTER_ROLE, params)
        })

        it(`can increase counter if account passed as param  has a minimum balance of 1 token`, async () => {
          //app Manager
          await executionTarget.increaseCounter(appManager)

          const actualCounter = await executionTarget.counter()
          assert.equal(actualCounter, INITIAL_COUNTER + 1)

          //account1
          await executionTarget.increaseCounter(account1)
        })

        it("can't increase counter if account passed as param does not have tokens", async () => {
          await assertRevert(executionTarget.increaseCounter(account2), 'APP_AUTH_FAILED')
        })

        context('required balance is 0', () => {
          beforeEach('set counter to 0', async () => {
            await acl.createPermission(appManager, executionTarget.address, SET_COUNTER_ROLE, appManager)

            //note that setting counter to 0 means setting the required balance to 0 for increaseCounter() function
            await executionTarget.setCounter(0)
          })

          it('all accounts with positive balance can increase counter', async () => {
            await executionTarget.increaseCounter(appManager)
            await executionTarget.increaseCounter(account1)
            await assertRevert(executionTarget.increaseCounter(account2), 'APP_AUTH_FAILED')
          })
        })

        context(`required balance is ${MOCK_TOKEN_BALANCE * 2}`, () => {
          beforeEach(`set counter to ${MOCK_TOKEN_BALANCE * 2}`, async () => {
            await acl.createPermission(appManager, executionTarget.address, SET_COUNTER_ROLE, appManager)

            //note that setting counter to MOCK_TOKEN_BALANCE * 2 means setting the required balance to MOCK_TOKEN_BALANCE * 2 for increaseCounter() function
            await executionTarget.setCounter(MOCK_TOKEN_BALANCE * 2)
          })

          it(`all accounts with less than ${MOCK_TOKEN_BALANCE * 2} tokens can't increase counter`, async () => {
            await assertRevert(executionTarget.increaseCounter(appManager), 'APP_AUTH_FAILED')
            await assertRevert(executionTarget.increaseCounter(account1), 'APP_AUTH_FAILED')
            await assertRevert(executionTarget.increaseCounter(account2), 'APP_AUTH_FAILED')
          })
        })
      })
    })
  })

  describe('app not initialized', () => {
    it('reverts on setting token', async () => {
      await assertRevert(oracle.setToken(mockErc20.address), 'APP_AUTH_FAILED')
    })

    it('reverts on setting balance', async () => {
      await assertRevert(oracle.setBalance(0), 'APP_AUTH_FAILED')
    })

    it('reverts on checking can perform', async () => {
      await assertRevert(oracle.canPerform(appManager, ANY_ADDR, '0x', []))
    })
  })
})
